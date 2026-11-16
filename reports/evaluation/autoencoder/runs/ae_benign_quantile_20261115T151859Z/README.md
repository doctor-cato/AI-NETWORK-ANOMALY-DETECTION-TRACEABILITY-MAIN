# Historical Autoencoder Run — `ae_benign_quantile_20261115T151859Z`

Bằng chứng thực nghiệm ban đầu (pre-P2-fix, commit `7f51390bfe4cea76a413733ac1882d8579fc4a34`) được lưu nguyên trạng tại thư mục này để đối chiếu minh bạch với run hiệu chỉnh mới:

- **Calibration method:** `benign_quantile` (`np.percentile(benign_scores, 95)`)
- **Frozen threshold:** `17234106.380850367`
- **Target FPR:** `0.05`
- **Empirical Validation FPR:** `0.05000142915670227` (`15,744 / 314,871` benign FPs — vượt `0.05` đúng `1` mẫu benign do nội suy quantile)
- **Held-out Test (`345,953` dòng):**
  - `TP=3,343`, `FP=15,189`, `TN=300,168`, `FN=27,253`
  - `Accuracy=0.8773`, `Precision=0.1804`, `Recall=0.1093` (`0.10926264871224997`), `F1=0.1361` (`0.13609347011887316`), `FPR=0.0482`, `ROC-AUC=0.6303`, `PR-AUC=0.1615`
  - Unknown holdout (`Worms`, `Backdoor`): `81 / 1,296` (`0.0625`)

Vì `empirical_val_fpr = 0.050001429 > 0.05`, cấu hình phát hành active `v0.6.0` được hiệu chỉnh lại trên **Validation-only** bằng `--calibration-method fpr_constrained --target-fpr 0.05` (không tune trên Held-out Test), đồng thời vẫn giữ nguyên toàn bộ kết quả gốc của run này.
