export type Lang = "vi" | "en";

export const repository =
  "https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN";
export const evidenceCommit = "36f63081bf30de98b1dc1058a780ae79ae2cf5b3";
export const source = (path: string) =>
  `${repository}/blob/${evidenceCommit}/${path}`;
export const issue = (number: number) => `${repository}/issues/${number}`;
export const pull = (number: number) => `${repository}/pull/${number}`;
export const href = (path = "", lang: Lang = "vi") => {
  const base = import.meta.env.BASE_URL.replace(/\/$/, "");
  const clean = path.replace(/^\//, "");
  const prefix = lang === "en" ? "/en" : "";
  return clean ? `${base}${prefix}/${clean}` : `${base}${prefix}/`;
};
