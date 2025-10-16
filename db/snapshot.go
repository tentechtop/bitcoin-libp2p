package db

// Represents a read-only view of the db at a specific point in time.
// If you don't need to read at a specific time, use the db directly.
type Snapshot interface {
	KeyValueReader
	Iterable
	Close() error
}

// Produces a read-only snapshot of the db
type Snapshotter interface {
	NewSnapshot() Snapshot
}
