# Verified schema: NF-UNSW-NB15-v3

## Contract tổng quát

CSV UTF-8 có `2365424` rows và 55 cột theo đúng thứ tự dưới đây. CSV không có kiểu vật
lý ngoài text; validator parse theo contract: IPv4 string, integer/number, binary target
và categorical target. `Label=0` tương ứng `Attack=Benign`; `Label=1` tương ứng một
trong chín attack categories.

### Sáu metadata/identifier fields — giữ cho grouping/Trace Engine, mặc định loại khỏi X

1. `FLOW_START_MILLISECONDS` — Unix epoch milliseconds, integer.
2. `FLOW_END_MILLISECONDS` — Unix epoch milliseconds, integer.
3. `IPV4_SRC_ADDR` — IPv4 string.
4. `L4_SRC_PORT` — integer trong `[0, 65535]`.
5. `IPV4_DST_ADDR` — IPv4 string.
6. `L4_DST_PORT` — integer trong `[0, 65535]`.

Khoảng timestamp quan sát: `2015-01-22T11:49:36.907Z` đến
`2015-02-18T12:29:25.011Z`. Không có row có end trước start trong lượt kiểm tra.

### Baseline ML feature contract — 47 ordered fields

Theo thứ tự CSV:

`PROTOCOL`, `L7_PROTO`, `IN_BYTES`, `IN_PKTS`, `OUT_BYTES`, `OUT_PKTS`, `TCP_FLAGS`,
`CLIENT_TCP_FLAGS`, `SERVER_TCP_FLAGS`, `FLOW_DURATION_MILLISECONDS`, `DURATION_IN`,
`DURATION_OUT`, `MIN_TTL`, `MAX_TTL`, `LONGEST_FLOW_PKT`, `SHORTEST_FLOW_PKT`,
`MIN_IP_PKT_LEN`, `MAX_IP_PKT_LEN`, `SRC_TO_DST_SECOND_BYTES`,
`DST_TO_SRC_SECOND_BYTES`, `RETRANSMITTED_IN_BYTES`, `RETRANSMITTED_IN_PKTS`,
`RETRANSMITTED_OUT_BYTES`, `RETRANSMITTED_OUT_PKTS`, `SRC_TO_DST_AVG_THROUGHPUT`,
`DST_TO_SRC_AVG_THROUGHPUT`, `NUM_PKTS_UP_TO_128_BYTES`,
`NUM_PKTS_128_TO_256_BYTES`, `NUM_PKTS_256_TO_512_BYTES`,
`NUM_PKTS_512_TO_1024_BYTES`, `NUM_PKTS_1024_TO_1514_BYTES`, `TCP_WIN_MAX_IN`,
`TCP_WIN_MAX_OUT`, `ICMP_TYPE`, `ICMP_IPV4_TYPE`, `DNS_QUERY_ID`, `DNS_QUERY_TYPE`,
`DNS_TTL_ANSWER`, `FTP_COMMAND_RET_CODE`, `SRC_TO_DST_IAT_MIN`,
`SRC_TO_DST_IAT_MAX`, `SRC_TO_DST_IAT_AVG`, `SRC_TO_DST_IAT_STDDEV`,
`DST_TO_SRC_IAT_MIN`, `DST_TO_SRC_IAT_MAX`, `DST_TO_SRC_IAT_AVG`,
`DST_TO_SRC_IAT_STDDEV`.

Các cột này được parse như numeric. `L7_PROTO` và rate/throughput values có thể dùng
biểu diễn decimal. Không áp integer coercion mù cho toàn bộ 47 cột.

### Targets — luôn loại khỏi X

54. `Label` — binary integer `0/1`.
55. `Attack` — `Benign`, `Analysis`, `Backdoor`, `DoS`, `Exploits`, `Fuzzers`,
    `Generic`, `Reconnaissance`, `Shellcode`, `Worms`.

Phân bố thực tế: Benign `2237731`; Fuzzers `33816`; Analysis `1226`; Backdoor
`4659`; DoS `5980`; Exploits `42748`; Generic `19651`; Reconnaissance `17074`;
Shellcode `2381`; Worms `158`.

## Quality findings trên file thật

- `SRC_TO_DST_SECOND_BYTES`: 63.425 blank và 59.068 `inf`.
- `DST_TO_SRC_SECOND_BYTES`: 122.493 `inf`.
- Không có invalid IPv4, port ngoài miền, negative numeric value, sai row width,
  invalid target hoặc mâu thuẫn Label/Attack trong lượt streaming check.
- Exact, ML-feature-equivalent, behavioral-v1 và group-overlap có contract riêng; real validator
  đã audit ba fingerprint đầu bằng disk-backed index, còn cross-split group audit chưa có split.

Status hiện tại là `SOURCE_INTEGRITY: PASS`, `RAW_QUALITY: FINDINGS_RECORDED`,
`ML_READY: BLOCKED`.
Preprocessing sau này phải quyết định imputation/drop policy từ **train only**; không
được thay dữ liệu raw tại chỗ.
