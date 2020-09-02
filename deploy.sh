docker build -t doc1981/multi-client:latest -t doc1981/multi-client:$SHA -f ./client/Dockerfile ./client
docker build -t doc1981/multi-server:latest -t doc1981/multi-server:$SHA -f ./server/Dockerfile ./server
docker build -t doc1981/multi-worker:latest -t doc1981/multi-worker:$SHA -f ./worker/Dockerfile ./worker

docker push doc1981/multi-client:latest
docker push doc1981/multi-server:latest
docker push doc1981/multi-worker:latest

docker push doc1981/multi-client:$SHA
docker push doc1981/multi-server:$SHA
docker push doc1981/multi-worker:$SHAs

kubectl apply -f k8s
kubectl set image deployments/server-deployment server=doc1981/multi-server:$SHA
kubectl set image deployments/client-deployment client=doc1981/multi-client:$SHA
kubectl set image deployments/worker-deployment worker=doc1981/multi-worker:$SHA