export const repository =
  "https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN";
export const evidenceCommit = "d1d16e1cafa79a8f515efa4b0a0e60a50a3b5e48";
export const source = (path: string) =>
  `${repository}/blob/${evidenceCommit}/${path}`;
export const issue = (number: number) => `${repository}/issues/${number}`;
export const pull = (number: number) => `${repository}/pull/${number}`;
export const href = (path = "") =>
  `${import.meta.env.BASE_URL.replace(/\/$/, "")}/${path.replace(/^\//, "")}`;
