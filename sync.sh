rsync -azvp --exclude 'headers' ./ roots@192.168.1.33:vip/
echo '
export GOPROXY=https://goproxy.cn
cd $HOME/vip
! [[ -d headers ]] && ln -s $HOME/ebpf/examples/headers headers
go generate
go build .
' | ssh roots@192.168.1.33 bash

rsync -azvp --exclude 'headers' roots@192.168.1.33:vip/ ./
