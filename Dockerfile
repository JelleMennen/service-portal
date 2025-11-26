FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o portal

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/portal .
EXPOSE 8080
CMD ["./portal"]