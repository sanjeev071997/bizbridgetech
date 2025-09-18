// Given TZ=Asia/Kolkata in env, this will use local midnight.
export const startOfDay = (d = new Date()) => {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate());
};
export const daysBetween = (from, to) => {
  const a = startOfDay(from);
  const b = startOfDay(to);
  return Math.floor((b - a) / (1000 * 60 * 60 * 24));
};
