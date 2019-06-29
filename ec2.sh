sudo yum install python3 -y

mkdir venv
cd venv
sudo pip3 install virtualenv
virtualenv flask

source flask/bin/activate
pip install -r ../req.txt

#flask/bin/pip install -r ../req.txt

