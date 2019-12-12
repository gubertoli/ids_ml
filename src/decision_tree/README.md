# Decision Tree Implmentation - eBPF/XDP and netfilter examples

### Blocking Probing Scan

Based on the following attibutes:

-- TCK Acknowlegment Number
-- TCP Urgent (URG) Flag
-- TCP Don't Fragment (DF) Flag
-- IP Time to Live (TTL) Field
-- IP Length
-- TCP Congestion Window Reduced (CWR) Flag
-- TCP Optional Maximum Segment Size (MSS) Value
-- TCP Reset (RST) Flag

Decision Tree trained with scikit-learn and inference algorithm extracted with package (emlearn)[https://github.com/emlearn/emlearn]
