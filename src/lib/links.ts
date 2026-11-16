export type Lang = "vi" | "en";

export const repository =
  "https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN";
export const evidenceCommit = "e5a1f896effc1981792d0e9c44232ae29cf4ffd4";
export const source = (path: string) =>
  `${repository}/blob/${evidenceCommit}/${path}`;
export const repoTree = (path: string, branch = "main") =>
  `${repository}/tree/${branch}/${path}`;
export const issue = (number: number) => `${repository}/issues/${number}`;
export const pull = (number: number) => `${repository}/pull/${number}`;
export const href = (path = "", lang: Lang = "vi") => {
  const base = import.meta.env.BASE_URL.replace(/\/$/, "");
  const clean = path.replace(/^\//, "");
  const prefix = lang === "en" ? "/en" : "";
  return clean ? `${base}${prefix}/${clean}` : `${base}${prefix}/`;
};
