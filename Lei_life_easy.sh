#!/bin/bash

clear

cd bin

rm device_driver2
rm reader
rm writer

echo "Remove all three files, now build up link"

ln -s /usr/local/eecs340/device_driver2
ln -s /usr/local/eecs340/reader
ln -s /usr/local/eecs340/writer

cd ../fifos

echo "Now change fifo permission"

chmod a+w ether2mon
chmod a+w ether2mux

echo "Done!"
