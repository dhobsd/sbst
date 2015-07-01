# sbst

Benchmarking various datastructures and algorithms for string lookups. For
more context, see also:

 * https://9vx.org/post/efficient-string-searching/
 * https://9vx.org/post/efficient-string-searching-pt2/

## Running Benchmarks

You'll need a dictionary and possibly to fiddle around with the `mkwords.pl`
script.

 * Run `make`
 * Run `./mkwords.pl [nwords] [nfiles] [depth] [prefix]`. If you intend to
   run more than 1 thread, `nfiles` must be more than 1. `depth` controls
   how deep to make the string. If you specify a `prefix`, generated strings
   will all contain that prefix.
 * Run `./bench-[foo] [nthreads] [nwords]` to benchmark a particular
   algorithm.

## Notes

The reported times contain:

 1. The time it took to parse input, allocate data structures, insert, and
    find the element just inserted.
 2. The time it took to find items in insertion order.

Times are measured in CPU cycles.

I'm sure there are ways to improve these tests. I'd be interested in
contributions for other data structures or other implementations of the same
data structures used here.

I'd also be interested in ports to other platforms and results.
