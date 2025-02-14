# calldigraph

A tool that outputs function and method call hierarchies as an intuitive directed graph.

- Recursively loads the specified source to optimize package loading
- Infers the actual implementation from methods of dependency-injected interfaces
- Integrates with `digraph`
- Comparison with `golang.org/x/tools/cmd/callgraph`
  - The standard `callgraph` emphasizes outputting a complete call graph
  - Existing algorithms can take several minutes because they need to load the entire project

## Installation

```
go install github.com/kis9a/calldigraph@latest
```

## With digraph

```
go install golang.org/x/tools/cmd/digraph@latest
```

## Example

```
$ calldigraph -type f -symbol 'github.com/example/api/usecase.(*BookingUsecaseImpl).GetPeriodic' .
"(*github.com/example/api/usecase.BookingUsecaseImpl).GetPeriodic" -> "(*github.com/example/api/repository.BookingImpl).GetBookingsBetween"
"(*github.com/example/api/repository.BookingImpl).GetBookingsBetween" -> "(*github.com/example/api/dto.Booking).GetBookingsBetween"
"(*github.com/example/api/usecase.BookingUsecaseImpl).GetPeriodic" -> "(*github.com/example/api/repository.BookingScheduleImpl).FetchByBookingIDs"
"(*github.com/example/api/repository.BookingScheduleImpl).FetchByBookingIDs" -> "(*github.com/example/api/dto.BookingSchedule).FetchByBookingIDs"
...
```

```
$ calldigraph -type f -symbol 'github.com/example/api/usecase.(*BookingUsecaseImpl).GetPeriodic' . \
  | digraph nodes

(*github.com/example/api/usecase.BookingUsecaseImpl).GetPeriodic
(*github.com/example/api/repository.BookingImpl).GetBookingsBetween
(*github.com/example/api/repository.BookingScheduleImpl).FetchByBookingIDs
(*github.com/example/api/dto.Booking).GetBookingsBetween
(*github.com/example/api/dto.BookingSchedule).FetchByBookingIDs
...
```

```
$ calldigraph -symbol 'github.com/example/api/usecase.(*BookingUsecaseImpl).GetPeriodic' . \
  | digraph preds "(*github.com/example/api/dto.Booking).GetBookingsBetween"

(*github.com/example/api/repository.BookingImpl).GetBookingsBetween
...
```

```
$ cat ./tmp/.exclude
github.com/example/api/dto

$ calldigraph -symbol 'github.com/example/api/usecase.(*BookingUsecaseImpl).GetPeriodic' . \
  | -exclude ./tmp/.exclude \
  | -exclude 'github.com/example/api/repository.*'
...
```
