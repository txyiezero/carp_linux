.PHONY: test clean

test:
	bash carp_basic.sh

clean:
	# Clean up any leftover test resources
	ip netns del carp_test_ns1 2>/dev/null || true
	ip netns del carp_test_ns2 2>/dev/null || true
	ip link del veth1a 2>/dev/null || true
