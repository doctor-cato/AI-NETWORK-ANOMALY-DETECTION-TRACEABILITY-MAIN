export type Lang = "vi" | "en";

export const repository =
  "https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN";
export const evidenceCommit = "18db24e637399d077312e60e4911e569b9b099d2";
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
