package file

import "testing"

func TestCapture(t *testing.T) {
	src, err := Open("capture_test.pcap")
	if err != nil {
		t.Fatalf("Error opening: %s", err)
	}

	var count uint64
	for {
		raw_pkt, err := src.Capture()
		if err != nil {
			t.Fatalf("Error reading: %s", err)
		}

		if raw_pkt == nil {
			break
		}

		count++
	}

	if count != 16 {
		t.Fatalf("Count mismatch: %d", count)
	}
}

func TestCaptureFilter(t *testing.T) {
	src, err := Open("capture_test.pcap")
	if err != nil {
		t.Fatalf("Error opening: %s", err)
	}

	err = src.ApplyFilter("arp")
	if err != nil {
		t.Fatalf("Error applying filter: %s", err)
	}

	var count uint64
	for {
		raw_pkt, err := src.Capture()
		if err != nil {
			t.Fatalf("Error reading: %s %d", err, count)
		}

		if raw_pkt == nil {
			break
		}

		count++
	}

	if count != 2 {
		t.Fatalf("Count mismatch: %d", count)
	}
}
