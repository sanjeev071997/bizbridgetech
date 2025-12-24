// Given TZ=Asia/Kolkata in env, this will use local midnight.
export const startOfDay = (date = new Date()) => {
  const istDate = new Date(
    date.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
  );

  return new Date(
    istDate.getFullYear(),
    istDate.getMonth(),
    istDate.getDate(),
    0, 0, 0, 0
  );
};

export const differenceInCalendarDays = (laterDate, earlierDate) => {
  const start = startOfDay(earlierDate);
  const end = startOfDay(laterDate);

  return Math.floor((end - start) / (1000 * 60 * 60 * 24));
};

export const addDays = (date, days) => {
  const d = startOfDay(date);
  d.setDate(d.getDate() + days);
  return d;
};

export const isLastDayOfMonth = (date = new Date()) => {
  const d = startOfDay(date);
  const nextDay = new Date(d);
  nextDay.setDate(d.getDate() + 1);
  return d.getMonth() !== nextDay.getMonth();
};

export const getMonthEndDate = (date = new Date()) => {
  const d = startOfDay(date);
  return new Date(
    d.getFullYear(),
    d.getMonth() + 1,
    0,
    23, 59, 59, 999
  );
};

export const getNextMonthEndDate = (date) => {
  if (!date) return null;

  const d = startOfDay(date);
  const currentMonthEnd = getMonthEndDate(d);

  if (d > currentMonthEnd) {
    const nextMonth = new Date(d);
    nextMonth.setMonth(nextMonth.getMonth() + 1);
    return getMonthEndDate(nextMonth);
  }

  return currentMonthEnd;
};

export const daysBetween = (from, to) => {
  return differenceInCalendarDays(to, from);
};

// IST-safe end of day (23:59:59.999)
export const endOfDay = (date = new Date()) => {
  const istDate = new Date(
    date.toLocaleString("en-US", { timeZone: "Asia/Kolkata" })
  );

  return new Date(
    istDate.getFullYear(),
    istDate.getMonth(),
    istDate.getDate(),
    23, 59, 59, 999
  );
};


export const getDaysInYear = (date) => {
  const year = new Date(date).getFullYear();
  // Leap year check: 4 rinda bhagavaguvudu, aadre 100 rinda alla, athava 400 rinda bhagavaguvudu
  return (year % 4 === 0 && year % 100 !== 0) || (year % 400 === 0) ? 366 : 365;
};

