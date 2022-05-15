package dkim

// DKIM Version 1
// Design Documentation Ref: https://datatracker.ietf.org/doc/html/rfc6376

const version = "1"
const prefix = "DKIM"

// signature verification failure does not force rejection of the message
