FROM golang:alpine

WORKDIR /app
RUN apk add --no-cache gcompat 
COPY vendor ./vendor/
COPY go.mod go.sum decryptor.go ./
RUN go build -o k8s-etcd-decryptor

FROM golang:alpine
COPY --from=0 /app/k8s-etcd-decryptor /go/k8s-etcd-decryptor
RUN apk add --no-cache bash
CMD ["/app/k8s-etcd-decryptor"]