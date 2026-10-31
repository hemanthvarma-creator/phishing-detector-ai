// =============================================================================
//  phish_url_engine.v
//
//  Streaming hardware phishing-URL detector.
//
//  A URL is streamed in one byte per clock over a valid/ready interface.
//  A single-pass parser FSM (SCHEME -> HOST -> PORT -> PATH) extracts
//  14 lexical features -- the hardware cousins of the features used by
//  app.py / create_model.py -- and a 3-stage pipelined linear classifier
//  (programmable signed weights + bias + threshold) produces a score and a
//  phishing verdict.
//
//  Features (all unsigned, saturating):
//    f0  URL-length bucket       (<54 -> 0, 54..75 -> 1, >75 -> 2)
//    f1  host is a dotted-quad IPv4 address
//    f2  '@' anywhere in the URL
//    f3  '//' redirect inside the path
//    f4  '-' in the host name
//    f5  number of dots in host  (leading "www." is stripped)
//    f6  scheme is not https
//    f7  explicit non-standard port (not 80/443, or malformed)
//    f8  host is a known URL shortener (CRC-16 lookup, same list as app.py)
//    f9  suspicious keyword hits (login, verify, secure, account, update,
//        signin, confirm, banking)            -- saturates at 7
//    f10 punycode label ("xn--") in host
//    f11 '%'-encoded bytes                      -- saturates at 15
//    f12 digits in host                         -- saturates at 15
//    f13 path depth ('/' count in path)         -- saturates at 15
//
//  Pipeline (all stages stall together on output back-pressure):
//    P0  byte parser / feature extraction   (features latched on s_last)
//    P1  14 parallel signed multiplies       f[i] * w[i]
//    P2  4-way partial-sum adder tree
//    P3  final sum + bias, threshold compare, hard-rule override
//
//  Throughput: 1 byte/clock, back-to-back URLs with no bubbles.
//  Latency   : 3 clocks from the s_last byte to m_valid.
//
//  Config port (cfg_we/cfg_addr/cfg_wdata):
//    addr 0..13 : weight i       (signed 8-bit, cfg_wdata[7:0])
//    addr 14    : bias           (signed 16-bit)
//    addr 15    : threshold      (signed 16-bit, phishing if score > thr)
//
//  Simulate (design + self-checking testbench in this file):
//    iverilog -g2005 -o tb hardware/phish_url_engine.v && vvp tb
// =============================================================================

`timescale 1ns/1ps

module phish_url_engine (
    input  wire               clk,
    input  wire               rst_n,

    // ---------------- URL byte stream (AXI-Stream-like) ----------------
    input  wire               s_valid,
    output wire               s_ready,
    input  wire [7:0]         s_data,
    input  wire               s_last,

    // ---------------- verdict stream ----------------
    output reg                m_valid,
    input  wire               m_ready,
    output reg  signed [19:0] m_score,
    output reg                m_phish,
    output reg  [13:0]        m_flags,    // bit i = (feature i != 0)
    output reg  [11:0]        m_len,

    // ---------------- weight / bias / threshold config ----------------
    input  wire               cfg_we,
    input  wire [3:0]         cfg_addr,
    input  wire [15:0]        cfg_wdata,

    // ---------------- statistics ----------------
    output reg  [31:0]        stat_total,
    output reg  [31:0]        stat_phish
);

    // -------------------------------------------------------------------------
    //  Parameters / constants
    // -------------------------------------------------------------------------
    localparam NF = 14;

    localparam [1:0] S_SCHEME = 2'd0,
                     S_HOST   = 2'd1,
                     S_PORT   = 2'd2,
                     S_PATH   = 2'd3;

    localparam [15:0] CRC_INIT = 16'hFFFF;

    // Default model (hand-tuned, mirrors the intuition of the RF model)
    localparam signed [7:0]  W0_DEF  =  8'sd6,   // length bucket
                             W1_DEF  =  8'sd30,  // IP host
                             W2_DEF  =  8'sd22,  // '@'
                             W3_DEF  =  8'sd16,  // '//' redirect
                             W4_DEF  =  8'sd10,  // hyphen
                             W5_DEF  =  8'sd5,   // dots
                             W6_DEF  =  8'sd8,   // not https
                             W7_DEF  =  8'sd14,  // odd port
                             W8_DEF  =  8'sd15,  // shortener
                             W9_DEF  =  8'sd9,   // keywords
                             W10_DEF =  8'sd20,  // punycode
                             W11_DEF =  8'sd2,   // %-encoding
                             W12_DEF =  8'sd2,   // host digits
                             W13_DEF =  8'sd1;   // path depth
    localparam signed [15:0] BIAS_DEF = -16'sd18;
    localparam signed [15:0] THR_DEF  =  16'sd0;

    // -------------------------------------------------------------------------
    //  Helper functions
    // -------------------------------------------------------------------------
    function [7:0] to_lower;
        input [7:0] ch;
        to_lower = (ch >= "A" && ch <= "Z") ? ch + 8'd32 : ch;
    endfunction

    function is_digit;
        input [7:0] ch;
        is_digit = (ch >= "0" && ch <= "9");
    endfunction

    function is_alpha;
        input [7:0] ch;
        is_alpha = (ch >= "a" && ch <= "z");
    endfunction

    // CRC-16/CCITT-FALSE, poly 0x1021, MSB first, one byte per call
    function [15:0] crc16_byte;
        input [15:0] crc_in;
        input [7:0]  b;
        integer k;
        reg [15:0] c;
        begin
            c = crc_in ^ {b, 8'h00};
            for (k = 0; k < 8; k = k + 1)
                c = c[15] ? ((c << 1) ^ 16'h1021) : (c << 1);
            crc16_byte = c;
        end
    endfunction

    // CRC-16 signatures of the shortener list in app.py (lower-case, no www.)
    function is_short;
        input [15:0] crc;
        begin
            case (crc)
                16'hDF52, // bit.ly
                16'h6249, // tinyurl.com
                16'hCA00, // goo.gl
                16'h52B3, // t.co
                16'h424F, // ow.ly
                16'hB286, // buff.ly
                16'h5A5D, // is.gd
                16'hC607, // adf.ly
                16'h7569, // shorte.st
                16'hEA96, // rebrand.ly
                16'h2DB9, // bl.ink
                16'hBCF1, // cutt.ly
                16'h307A, // t.ly
                16'h1C77: // rb.gy
                    is_short = 1'b1;
                default:
                    is_short = 1'b0;
            endcase
        end
    endfunction

    // Multi-pattern keyword matcher on a sliding window.
    // h = {7 previous bytes, current byte}; newest byte in h[7:0].
    function kw_match;
        input [63:0] h;
        begin
            kw_match = (h[39:0] == "login")   ||
                       (h[47:0] == "verify")  ||
                       (h[47:0] == "secure")  ||
                       (h[55:0] == "account") ||
                       (h[47:0] == "update")  ||
                       (h[47:0] == "signin")  ||
                       (h[55:0] == "confirm") ||
                       (h[55:0] == "banking");
        end
    endfunction

    // Does byte ch match the expected scheme character at position pos?
    // Accepts "http://" and "https://".
    function sch_match;
        input [11:0] pos;
        input        https;
        input [7:0]  ch;
        begin
            case (pos)
                12'd0:   sch_match = (ch == "h");
                12'd1:   sch_match = (ch == "t");
                12'd2:   sch_match = (ch == "t");
                12'd3:   sch_match = (ch == "p");
                12'd4:   sch_match = (ch == "s") || (ch == ":");
                12'd5:   sch_match = https ? (ch == ":") : (ch == "/");
                12'd6:   sch_match = (ch == "/");
                12'd7:   sch_match = https && (ch == "/");
                default: sch_match = 1'b0;
            endcase
        end
    endfunction

    // -------------------------------------------------------------------------
    //  Configuration registers
    // -------------------------------------------------------------------------
    reg signed [7:0]  w [0:NF-1];
    reg signed [15:0] bias;
    reg signed [15:0] thr;
    integer i;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            w[0]  <= W0_DEF;  w[1]  <= W1_DEF;  w[2]  <= W2_DEF;
            w[3]  <= W3_DEF;  w[4]  <= W4_DEF;  w[5]  <= W5_DEF;
            w[6]  <= W6_DEF;  w[7]  <= W7_DEF;  w[8]  <= W8_DEF;
            w[9]  <= W9_DEF;  w[10] <= W10_DEF; w[11] <= W11_DEF;
            w[12] <= W12_DEF; w[13] <= W13_DEF;
            bias  <= BIAS_DEF;
            thr   <= THR_DEF;
        end else if (cfg_we) begin
            case (cfg_addr)
                4'd14:   bias <= cfg_wdata;
                4'd15:   thr  <= cfg_wdata;
                default: w[cfg_addr] <= cfg_wdata[7:0];
            endcase
        end
    end

    // -------------------------------------------------------------------------
    //  Global flow control: everything advances unless the output is stuck
    // -------------------------------------------------------------------------
    wire stall = m_valid & ~m_ready;
    wire adv   = ~stall;
    assign s_ready = adv;
    wire fire  = s_valid & s_ready;

    // -------------------------------------------------------------------------
    //  P0 : parser state
    // -------------------------------------------------------------------------
    reg [1:0]  st;
    reg [11:0] len;
    reg        sch_s;        // saw the 's' of https
    reg        is_https;
    // host
    reg [7:0]  h_len;
    reg [3:0]  h_dots;
    reg [3:0]  h_digits;
    reg        h_hyph;
    reg        ip_bad;
    reg [9:0]  oct_val;
    reg [2:0]  oct_dig;
    reg        www_ok;
    reg [15:0] crc;
    reg [23:0] h_win;
    reg        puny;
    // port
    reg        port_seen;
    reg [16:0] port_val;
    reg        port_bad;
    // path / global
    reg [3:0]  depth;
    reg        prev_slash;
    reg        redirect;
    reg        has_at;
    reg [3:0]  pct;
    reg [2:0]  kw;
    reg [55:0] win;

    // next-state copies
    reg [1:0]  n_st;
    reg [11:0] n_len;
    reg        n_sch_s, n_is_https;
    reg [7:0]  n_h_len;
    reg [3:0]  n_h_dots, n_h_digits;
    reg        n_h_hyph, n_ip_bad;
    reg [9:0]  n_oct_val;
    reg [2:0]  n_oct_dig;
    reg        n_www_ok;
    reg [15:0] n_crc;
    reg [23:0] n_h_win;
    reg        n_puny;
    reg        n_port_seen;
    reg [16:0] n_port_val;
    reg        n_port_bad;
    reg [3:0]  n_depth;
    reg        n_prev_slash, n_redirect, n_has_at;
    reg [3:0]  n_pct;
    reg [2:0]  n_kw;
    reg [55:0] n_win;

    // combinational scratch
    reg [7:0]  c;
    reg        do_host;
    reg        sch_final;
    reg [10:0] oct_tmp;
    reg [20:0] port_tmp;

    always @* begin
        // ---- hold by default ----
        n_st        = st;        n_len       = len;
        n_sch_s     = sch_s;     n_is_https  = is_https;
        n_h_len     = h_len;     n_h_dots    = h_dots;
        n_h_digits  = h_digits;  n_h_hyph    = h_hyph;
        n_ip_bad    = ip_bad;    n_oct_val   = oct_val;
        n_oct_dig   = oct_dig;   n_www_ok    = www_ok;
        n_crc       = crc;       n_h_win     = h_win;
        n_puny      = puny;      n_port_seen = port_seen;
        n_port_val  = port_val;  n_port_bad  = port_bad;
        n_depth     = depth;     n_prev_slash= prev_slash;
        n_redirect  = redirect;  n_has_at    = has_at;
        n_pct       = pct;       n_kw        = kw;
        n_win       = win;

        c         = to_lower(s_data);
        do_host   = 1'b0;
        sch_final = 1'b0;
        oct_tmp   = 11'd0;
        port_tmp  = 21'd0;

        if (fire) begin
            // ---------------- global, every byte ----------------
            n_len = (len == 12'hFFF) ? len : len + 12'd1;
            n_win = {win[47:0], c};
            if (kw_match({win, c}) && kw != 3'd7)
                n_kw = kw + 3'd1;
            if (c == "@")
                n_has_at = 1'b1;

            // ---------------- per-state ----------------
            case (st)
            S_SCHEME: begin
                if (sch_match(len, sch_s, c)) begin
                    if (len == 12'd4 && c == "s")
                        n_sch_s = 1'b1;
                    sch_final = (c == "/") && (sch_s ? (len == 12'd7)
                                                     : (len == 12'd6));
                    if (sch_final) begin
                        // scheme complete: discard speculative host state
                        n_st       = S_HOST;
                        n_is_https = sch_s;
                        n_h_len    = 8'd0;   n_h_dots   = 4'd0;
                        n_h_digits = 4'd0;   n_h_hyph   = 1'b0;
                        n_ip_bad   = 1'b0;   n_oct_val  = 10'd0;
                        n_oct_dig  = 3'd0;   n_www_ok   = 1'b1;
                        n_crc      = CRC_INIT;
                        n_h_win    = 24'd0;  n_puny     = 1'b0;
                    end else if (is_alpha(c)) begin
                        // speculatively treat scheme letters as host
                        do_host = 1'b1;
                    end
                end else if (len <= 12'd4 || (len == 12'd5 && sch_s)) begin
                    // no "://" yet: there was no scheme, it's a bare host
                    n_st    = S_HOST;
                    do_host = 1'b1;
                end else begin
                    // malformed scheme after ':' -- treat rest as opaque path
                    n_st = S_PATH;
                end
            end

            S_HOST:
                do_host = 1'b1;

            S_PORT: begin
                if (is_digit(c)) begin
                    port_tmp = port_val * 10 + (c - "0");
                    if (port_tmp > 21'd65535)
                        n_port_bad = 1'b1;
                    else
                        n_port_val = port_tmp[16:0];
                end else if (c == "/") begin
                    n_st         = S_PATH;
                    n_depth      = 4'd1;
                    n_prev_slash = 1'b1;
                end else if (c == "?" || c == "#") begin
                    n_st = S_PATH;
                end else begin
                    n_port_bad = 1'b1;
                end
            end

            S_PATH: begin
                if (c == "/") begin
                    if (depth != 4'hF) n_depth = depth + 4'd1;
                    if (prev_slash)    n_redirect = 1'b1;
                    n_prev_slash = 1'b1;
                end else begin
                    n_prev_slash = 1'b0;
                    if (c == "%" && pct != 4'hF)
                        n_pct = pct + 4'd1;
                end
            end
            endcase

            // ---------------- host character processing ----------------
            if (do_host) begin
                case (c)
                "/": begin
                    n_st         = S_PATH;
                    n_depth      = 4'd1;
                    n_prev_slash = 1'b1;
                end
                "?", "#":
                    n_st = S_PATH;
                ":": begin
                    n_st        = S_PORT;
                    n_port_seen = 1'b1;
                end
                "@": begin
                    // user-info before '@' -- the real host follows
                    n_h_len    = 8'd0;   n_h_dots   = 4'd0;
                    n_h_digits = 4'd0;   n_h_hyph   = 1'b0;
                    n_ip_bad   = 1'b0;   n_oct_val  = 10'd0;
                    n_oct_dig  = 3'd0;   n_www_ok   = 1'b1;
                    n_crc      = CRC_INIT;
                    n_h_win    = 24'd0;  n_puny     = 1'b0;
                end
                default: begin
                    if (h_len != 8'hFF) n_h_len = h_len + 8'd1;
                    n_crc   = crc16_byte(crc, c);
                    n_h_win = {h_win[15:0], c};
                    if ({h_win, c} == "xn--")
                        n_puny = 1'b1;

                    // "www." prefix tracking
                    if (h_len < 8'd3 && c != "w")
                        n_www_ok = 1'b0;

                    if (c == ".") begin
                        if (h_len == 8'd3 && www_ok) begin
                            // strip leading "www." from hash and dot count
                            n_crc = CRC_INIT;
                        end else if (h_dots != 4'hF) begin
                            n_h_dots = h_dots + 4'd1;
                        end
                        if (oct_dig == 3'd0) n_ip_bad = 1'b1;
                        n_oct_val = 10'd0;
                        n_oct_dig = 3'd0;
                    end else if (is_digit(c)) begin
                        if (h_digits != 4'hF) n_h_digits = h_digits + 4'd1;
                        oct_tmp   = oct_val * 10 + (c - "0");
                        n_oct_val = oct_tmp[9:0];
                        n_oct_dig = oct_dig + 3'd1;
                        if (oct_dig >= 3'd3 || oct_tmp > 11'd255)
                            n_ip_bad = 1'b1;
                    end else begin
                        if (c == "-") n_h_hyph = 1'b1;
                        n_ip_bad = 1'b1;
                    end
                end
                endcase
            end
        end
    end

    // ---- final feature computation (valid on the s_last beat) ----
    wire        f_ip    = ~n_ip_bad && (n_h_dots == 4'd3) &&
                          (n_oct_dig != 3'd0) && (n_h_len != 8'd0);
    wire        f_short = (n_h_len != 8'd0) && is_short(n_crc);
    wire        f_port  = n_port_seen &&
                          (n_port_bad || (n_port_val != 17'd80 &&
                                          n_port_val != 17'd443));
    wire [1:0]  f_lenb  = (n_len < 12'd54) ? 2'd0 :
                          (n_len <= 12'd75) ? 2'd1 : 2'd2;

    wire [8*NF-1:0] feat_next = {
        4'd0, n_depth,              // f13
        4'd0, n_h_digits,           // f12
        4'd0, n_pct,                // f11
        7'd0, n_puny,               // f10
        5'd0, n_kw,                 // f9
        7'd0, f_short,              // f8
        7'd0, f_port,               // f7
        7'd0, ~n_is_https,          // f6
        4'd0, n_h_dots,             // f5
        7'd0, n_h_hyph,             // f4
        7'd0, n_redirect,           // f3
        7'd0, n_has_at,             // f2
        7'd0, f_ip,                 // f1
        6'd0, f_lenb                // f0
    };

    // P0 output registers
    reg              v0;
    reg [8*NF-1:0]   feat0;
    reg              ovr0;
    reg [11:0]       len0;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            st <= S_SCHEME; len <= 12'd0; sch_s <= 1'b0; is_https <= 1'b0;
            h_len <= 8'd0; h_dots <= 4'd0; h_digits <= 4'd0; h_hyph <= 1'b0;
            ip_bad <= 1'b0; oct_val <= 10'd0; oct_dig <= 3'd0; www_ok <= 1'b1;
            crc <= CRC_INIT; h_win <= 24'd0; puny <= 1'b0;
            port_seen <= 1'b0; port_val <= 17'd0; port_bad <= 1'b0;
            depth <= 4'd0; prev_slash <= 1'b0; redirect <= 1'b0;
            has_at <= 1'b0; pct <= 4'd0; kw <= 3'd0; win <= 56'd0;
            v0 <= 1'b0; feat0 <= {8*NF{1'b0}}; ovr0 <= 1'b0; len0 <= 12'd0;
        end else if (adv) begin
            v0 <= fire & s_last;
            if (fire & s_last) begin
                feat0 <= feat_next;
                ovr0  <= f_ip & n_has_at;   // hard rule: IP host + '@'
                len0  <= n_len;
                // reset parser for the next URL
                st <= S_SCHEME; len <= 12'd0; sch_s <= 1'b0; is_https <= 1'b0;
                h_len <= 8'd0; h_dots <= 4'd0; h_digits <= 4'd0;
                h_hyph <= 1'b0; ip_bad <= 1'b0; oct_val <= 10'd0;
                oct_dig <= 3'd0; www_ok <= 1'b1; crc <= CRC_INIT;
                h_win <= 24'd0; puny <= 1'b0;
                port_seen <= 1'b0; port_val <= 17'd0; port_bad <= 1'b0;
                depth <= 4'd0; prev_slash <= 1'b0; redirect <= 1'b0;
                has_at <= 1'b0; pct <= 4'd0; kw <= 3'd0; win <= 56'd0;
            end else begin
                st <= n_st; len <= n_len; sch_s <= n_sch_s;
                is_https <= n_is_https;
                h_len <= n_h_len; h_dots <= n_h_dots; h_digits <= n_h_digits;
                h_hyph <= n_h_hyph; ip_bad <= n_ip_bad; oct_val <= n_oct_val;
                oct_dig <= n_oct_dig; www_ok <= n_www_ok; crc <= n_crc;
                h_win <= n_h_win; puny <= n_puny;
                port_seen <= n_port_seen; port_val <= n_port_val;
                port_bad <= n_port_bad;
                depth <= n_depth; prev_slash <= n_prev_slash;
                redirect <= n_redirect; has_at <= n_has_at; pct <= n_pct;
                kw <= n_kw; win <= n_win;
            end
        end
    end

    // -------------------------------------------------------------------------
    //  P1 : parallel multiplies
    // -------------------------------------------------------------------------
    reg               v1;
    reg signed [16:0] prod [0:NF-1];
    reg [8*NF-1:0]    feat1;
    reg               ovr1;
    reg [11:0]        len1;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            v1 <= 1'b0; feat1 <= {8*NF{1'b0}}; ovr1 <= 1'b0; len1 <= 12'd0;
            for (i = 0; i < NF; i = i + 1) prod[i] <= 17'sd0;
        end else if (adv) begin
            v1    <= v0;
            feat1 <= feat0;
            ovr1  <= ovr0;
            len1  <= len0;
            for (i = 0; i < NF; i = i + 1)
                prod[i] <= $signed({1'b0, feat0[8*i +: 8]}) * w[i];
        end
    end

    // -------------------------------------------------------------------------
    //  P2 : adder tree (4 partial sums)
    // -------------------------------------------------------------------------
    reg               v2;
    reg signed [19:0] psum [0:3];
    reg [8*NF-1:0]    feat2;
    reg               ovr2;
    reg [11:0]        len2;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            v2 <= 1'b0; feat2 <= {8*NF{1'b0}}; ovr2 <= 1'b0; len2 <= 12'd0;
            for (i = 0; i < 4; i = i + 1) psum[i] <= 20'sd0;
        end else if (adv) begin
            v2    <= v1;
            feat2 <= feat1;
            ovr2  <= ovr1;
            len2  <= len1;
            psum[0] <= prod[0]  + prod[1]  + prod[2]  + prod[3];
            psum[1] <= prod[4]  + prod[5]  + prod[6]  + prod[7];
            psum[2] <= prod[8]  + prod[9]  + prod[10] + prod[11];
            psum[3] <= prod[12] + prod[13];
        end
    end

    // -------------------------------------------------------------------------
    //  P3 : final sum, threshold, output register, statistics
    // -------------------------------------------------------------------------
    wire signed [19:0] score_w = psum[0] + psum[1] + psum[2] + psum[3] + bias;

    reg [13:0] flags_w;
    always @* begin
        for (i = 0; i < NF; i = i + 1)
            flags_w[i] = |feat2[8*i +: 8];
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            m_valid    <= 1'b0;
            m_score    <= 20'sd0;
            m_phish    <= 1'b0;
            m_flags    <= 14'd0;
            m_len      <= 12'd0;
            stat_total <= 32'd0;
            stat_phish <= 32'd0;
        end else begin
            if (adv) begin
                m_valid <= v2;
                if (v2) begin
                    m_score <= score_w;
                    m_phish <= ovr2 | (score_w > thr);
                    m_flags <= flags_w;
                    m_len   <= len2;
                end
            end
            if (m_valid && m_ready) begin
                stat_total <= stat_total + 32'd1;
                if (m_phish) stat_phish <= stat_phish + 32'd1;
            end
        end
    end

endmodule


// =============================================================================
//  Self-checking testbench
//    - expected scores come from an independent software reference model
//    - phase 1: full-rate input, m_ready always high
//    - phase 2: random input gaps and random output back-pressure
//    - phase 3: reprogram a weight through the config port
// =============================================================================
`ifndef SYNTHESIS
module phish_url_engine_tb;

    reg         clk = 1'b0;
    reg         rst_n = 1'b0;
    reg         s_valid = 1'b0;
    wire        s_ready;
    reg  [7:0]  s_data = 8'd0;
    reg         s_last = 1'b0;
    wire        m_valid;
    reg         m_ready = 1'b1;
    wire signed [19:0] m_score;
    wire        m_phish;
    wire [13:0] m_flags;
    wire [11:0] m_len;
    reg         cfg_we = 1'b0;
    reg  [3:0]  cfg_addr = 4'd0;
    reg  [15:0] cfg_wdata = 16'd0;
    wire [31:0] stat_total, stat_phish;

    always #5 clk = ~clk;

    phish_url_engine dut (
        .clk(clk), .rst_n(rst_n),
        .s_valid(s_valid), .s_ready(s_ready), .s_data(s_data), .s_last(s_last),
        .m_valid(m_valid), .m_ready(m_ready),
        .m_score(m_score), .m_phish(m_phish), .m_flags(m_flags), .m_len(m_len),
        .cfg_we(cfg_we), .cfg_addr(cfg_addr), .cfg_wdata(cfg_wdata),
        .stat_total(stat_total), .stat_phish(stat_phish)
    );

    // ---------------- test vectors ----------------
    localparam NT = 12;
    reg [8*96-1:0]     url  [0:NT-1];
    reg signed [19:0]  exp_s[0:NT-1];
    reg                exp_p[0:NT-1];

    initial begin
        url[0]  = "https://www.google.com";
        url[1]  = "https://github.com/hemanthvarma-creator/phishing-detector-ai";
        url[2]  = "http://192.168.10.5/paypal/login/verify.php";
        url[3]  = "http://secure-paypal-account-update.com/signin";
        url[4]  = "https://bit.ly/3xYzAbC";
        url[5]  = "http://user@10.0.0.1:8080//redirect?u=bank";
        url[6]  = "HTTPS://WWW.Example.COM/About";
        url[7]  = "xn--pple-43d.com/login";
        url[8]  = "http://a.b.c.d.e.example.net/%2e%2e/%2f/confirm";
        url[9]  = "example.org:443/index.html";
        url[10] = "https://mybank.com.verify-account.info/online-banking/login";
        url[11] = "https://en.wikipedia.org/wiki/Phishing";
    end

    // expected results from an independent software reference model
    initial begin
        exp_s[0]  = -13; exp_p[0]  = 1'b0;
        exp_s[1]  =  -5; exp_p[1]  = 1'b0;
        exp_s[2]  =  74; exp_p[2]  = 1'b1;
        exp_s[3]  =  42; exp_p[3]  = 1'b1;
        exp_s[4]  =   3; exp_p[4]  = 1'b1;
        exp_s[5]  =  99; exp_p[5]  = 1'b1;
        exp_s[6]  = -12; exp_p[6]  = 1'b0;
        exp_s[7]  =  39; exp_p[7]  = 1'b1;
        exp_s[8]  =  38; exp_p[8]  = 1'b1;
        exp_s[9]  =  -4; exp_p[9]  = 1'b0;
        exp_s[10] =  51; exp_p[10] = 1'b1;
        exp_s[11] =  -6; exp_p[11] = 1'b0;
    end

    // ---------------- driver ----------------
    reg rand_gaps = 1'b0;

    // order of URLs sent, so the scoreboard knows what to expect
    integer sentq [0:255];
    integer wr = 0;

    task send_url;
        input integer idx;
        reg [8*96-1:0] s;
        integer n, k;
        begin
            s = url[idx];
            sentq[wr] = idx;
            wr = wr + 1;
            n = 96;
            while (n > 0 && s[8*(n-1) +: 8] == 8'd0) n = n - 1;
            for (k = n - 1; k >= 0; k = k - 1) begin
                if (rand_gaps) begin
                    while ($random % 4 == 0) begin
                        s_valid <= 1'b0;
                        @(posedge clk);
                    end
                end
                s_valid <= 1'b1;
                s_data  <= s[8*k +: 8];
                s_last  <= (k == 0);
                @(posedge clk);
                while (!s_ready) @(posedge clk);
            end
            s_valid <= 1'b0;
            s_last  <= 1'b0;
        end
    endtask

    // ---------------- monitor / scoreboard ----------------
    integer got = 0, errors = 0, phase = 1, ix;

    always @(posedge clk) begin
        if (m_valid && m_ready) begin
            ix = sentq[got];
            if (m_score !== exp_s[ix] || m_phish !== exp_p[ix]) begin
                $display("  [FAIL] #%0d %0s : score=%0d phish=%0b (exp %0d/%0b)",
                         got, url[ix], m_score, m_phish, exp_s[ix], exp_p[ix]);
                errors = errors + 1;
            end else if (phase != 2) begin
                $display("  %-8s score=%4d len=%3d flags=%b  %0s",
                         m_phish ? "PHISHING" : "legit", m_score, m_len,
                         m_flags, url[ix]);
            end
            got = got + 1;
        end
    end

    // random back-pressure in phase 2
    always @(posedge clk)
        if (phase == 2) m_ready <= ($random % 3 != 0);
        else            m_ready <= 1'b1;

    integer t;
    initial begin
        $display("=== phish_url_engine testbench ===");
        repeat (3) @(posedge clk);
        rst_n <= 1'b1;
        @(posedge clk);

        // ---- phase 1: back-to-back, full rate ----
        $display("-- phase 1: full rate --");
        for (t = 0; t < NT; t = t + 1) send_url(t);
        while (got < NT) @(posedge clk);

        // ---- phase 2: random stalls on both sides, 3 rounds ----
        $display("-- phase 2: random gaps + back-pressure (36 URLs) --");
        phase     = 2;
        rand_gaps = 1'b1;
        for (t = 0; t < 3*NT; t = t + 1) send_url(t % NT);
        while (got < 4*NT) @(posedge clk);
        phase     = 3;
        rand_gaps = 1'b0;

        // ---- phase 3: config port -- zero the '@' weight ----
        $display("-- phase 3: reprogram w[2] (@) = 0 --");
        @(posedge clk);
        cfg_we <= 1'b1; cfg_addr <= 4'd2; cfg_wdata <= 16'd0;
        @(posedge clk);
        cfg_we <= 1'b0;
        exp_s[5] = exp_s[5] - 22;          // url[5] contains '@'
        send_url(5);
        while (got < 4*NT + 1) @(posedge clk);
        repeat (2) @(posedge clk);

        $display("stats: total=%0d phishing=%0d", stat_total, stat_phish);
        if (errors == 0) $display("=== PASS (%0d verdicts checked) ===", got);
        else             $display("=== FAIL: %0d mismatches ===", errors);
        $finish;
    end

    // watchdog
    initial begin
        #200000;
        $display("=== FAIL: timeout ===");
        $finish;
    end

endmodule
`endif
