// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigma

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// A Date is a Gregorian date. The zero value is January 1, year 1.
type Date struct {
	_ [0]func() // prevent direct comparisons

	year, month, day int
}

// NewDate returns the Date with the given values.
// The arguments may be outside their usual ranges
// and will be normalized during the conversion.
func NewDate(year int, month time.Month, day int) Date {
	d := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	return Date{year: d.Year() - 1, month: int(d.Month() - 1), day: d.Day() - 1}
}

// ParseDate parses a date in Sigma format (i.e. "YYYY/MM/DD").
func ParseDate(s string) (Date, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 3 {
		// The spec says ISO-8601 format is accepted.
		newParts := strings.Split(s, "-")
		if len(newParts) != 3 {
			return Date{}, fmt.Errorf("parse sigma date %q: unknown format", s)
		}
		parts = newParts
	}
	year, err := strconv.Atoi(parts[0])
	if err != nil {
		return Date{}, fmt.Errorf("parse sigma date %q: year: %v", s, err)
	}
	if year < 100 {
		return Date{}, fmt.Errorf("parse sigma date %q: short years not allowed", s)
	}
	month, err := strconv.Atoi(parts[1])
	if err != nil {
		return Date{}, fmt.Errorf("parse sigma date %q: month: %v", s, err)
	}
	if !(1 <= month && month <= 12) {
		return Date{}, fmt.Errorf("parse sigma date %q: invalid month %d", s, month)
	}
	day, err := strconv.Atoi(parts[2])
	if err != nil {
		return Date{}, fmt.Errorf("parse sigma date %q: day: %v", s, err)
	}
	if !(1 <= day && day <= 31) {
		return Date{}, fmt.Errorf("parse sigma date %q: invalid day %d", s, day)
	}
	return NewDate(year, time.Month(month), day), nil
}

// Year returns the year in which d occurs.
func (d Date) Year() int {
	return d.year + 1
}

// Month returns the month of the year specified by d.
func (d Date) Month() time.Month {
	return time.Month(d.month + 1)
}

// Day returns the day of the month specified by d.
func (d Date) Day() int {
	return d.day + 1
}

// Equal reports whether d equals d2.
func (d Date) Equal(d2 Date) bool {
	return d.year == d2.year && d.month == d2.month && d.day == d2.day
}

// IsZero reports d is the zero value.
func (d Date) IsZero() bool {
	return d.year == 0 && d.month == 0 && d.day == 0
}

// String returns the date in Sigma's YYYY/MM/DD format, like "2006-01-02".
func (d Date) String() string {
	return fmt.Sprintf("%04d/%02d/%02d", d.Year(), int(d.Month()), d.Day())
}

// MarshalText formats the date in Sigma's YYYY/MM/DD format, like "2006-01-02".
func (d Date) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalText parses a date in Sigma format (i.e. "YYYY/MM/DD").
func (d *Date) UnmarshalText(data []byte) error {
	newDate, err := ParseDate(string(data))
	if err != nil {
		return err
	}
	*d = newDate
	return nil
}
