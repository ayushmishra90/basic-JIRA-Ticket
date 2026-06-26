# ---- Build stage ----
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Cache dependencies first.
COPY go.mod go.sum ./
RUN go mod download

# Build a static binary (no CGO) so it runs in a minimal image.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /ticket-system .

# ---- Runtime stage ----
FROM alpine:3.20

# Run as a non-root user.
RUN adduser -D -u 10001 appuser

WORKDIR /app
COPY --from=builder /ticket-system /app/ticket-system

USER appuser

# The service listens on 8080 by default (overridable via PORT).
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/app/ticket-system"]
