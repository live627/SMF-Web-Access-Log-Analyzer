`country.php` is a script that implements functions to load country data from a compressed CSV file into a cache and perform lookups based on IP addresses.
It includes binary search methods and jump table optimizations for efficient country code retrieval.

```
Loaded in 0.474s
Peak memory: 168 MB
8.8.8.8 → US
```

Loading into an array works, but uses too much memory.

```
Loaded in 0.474s
Peak memory: 4.01 MB
```

Using a string buffer results in **low memory usage** — good!
Negligible speed difference. I suppose array allocations are quite efficient for the space they consume.

```
✅ Verified: country_cache and country_cache_bin have identical records and order.
```

The file is already sorted, so a binary search works as expected.

```
Looked up 100000 IPs in 0.275s (363,683 lookups/sec, hits=100000)
```

Binary search is fast, as expected.

```
Looked up 100000 IPs in 0.178s (561,353 lookups/sec, hits=100000)
Checked for equal results for 100000 IPs in 0.414s (241,781 lookups/sec, hits=100000)
```

Look at that — binary search on a binary blob is even faster!
Is array access really that slow?

```
Loaded in 0.016s
Peak memory: 8.13 KB
```

I built a jump table to limit ranges by indexing the offset of the first byte of each IP address.

```
111.40.184.208 → CN
Looked up 100000 IPs in 0.112s (895,880 lookups/sec, hits=100000)
Checked for equal results for 100000 IPs in 0.342s (292,234 lookups/sec, hits=100000)
```

Now lookups are even faster!
And each search still hits correctly — verified against the array.

Just for fun, I tried implementing a **radix-2 trie** using raw binary digits as keys, but it took twice the memory of the array and six seconds to load.
And this was *with* CIDR conversion, which ChatGPT told me would reduce nodes.
Anyway, searching that structure ended up taking roughly the same time as the binary search on the array — so out it goes.
(I’m not writing all this test code on my own, though.)

I then implemented a **trie based on bytes**, also using CIDR ranges.
It ran out of memory. Increased the limit to 4 GB — it took a bit longer before hitting that wall again.
Deleted it. I want a version of this script that can run on shared hosts where memory is limited.
