FROM buildpack-deps:trixie-scm AS builder

ENV GOPATH /gopath/
ENV PATH $GOPATH/bin:$PATH
ARG buildImageTag


WORKDIR /gopath/src/k8s.io
RUN git clone https://github.com/kubernetes/autoscaler.git -b "vertical-pod-autoscaler-${buildImageTag}"  # legit:ignore
WORKDIR /gopath/src/k8s.io/autoscaler/vertical-pod-autoscaler

RUN go get golang.org/x/net@v0.39.0 && \
    go get google.golang.org/protobuf@v1.33.0 && \
    go get golang.org/x/oauth2@v0.27.0 && \
    go mod tidy && go mod vendor

ARG TARGETOS TARGETARCH

# Build the vpa-admission-updater binary
RUN CGO_ENABLED=0 LD_FLAGS=-s GOARCH=$TARGETARCH GOOS=$TARGETOS go build -C pkg/updater -mod vendor -ldflags="-s" -o updater


FROM gcr.io/distroless/static:latest
USER 0

COPY --from=builder /gopath/src/k8s.io/autoscaler/vertical-pod-autoscaler/pkg/updater/updater /updater

ENTRYPOINT ["/updater"]
CMD ["--v=4", "--stderrthreshold=info"]
