FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/asi ./cmd/asi

FROM alpine:3.22
RUN apk add --no-cache nmap nmap-scripts ca-certificates
COPY --from=build /out/asi /usr/local/bin/asi
ENV ASI_LISTEN=:8080
EXPOSE 8080
ENTRYPOINT ["asi"]
CMD ["serve"]
