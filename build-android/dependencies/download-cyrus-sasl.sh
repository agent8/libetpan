#! /bin/bash -

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

version=2.1.27
ARCHIVE=cyrus-sasl-$version
ARCHIVE_NAME=$ARCHIVE.tar.gz
ARCHIVE_PATCH=$ARCHIVE.patch
#url=ftp://ftp.andrew.cmu.edu/pub/cyrus-mail/$ARCHIVE_NAME
#url=ftp://ftp.cyrusimap.org/cyrus-sasl/$ARCHIVE_NAME
#url=https://www.cyrusimap.org/releases/$ARCHIVE_NAME
url=https://github.com/cyrusimap/cyrus-sasl/releases/download/$ARCHIVE/$ARCHIVE_NAME

scriptdir="`pwd`"

current_dir="$scriptdir"

dest_dir="$scriptdir/../../build-mac/dependencies/packages"

# download package file

if test -f "$dest_dir/$ARCHIVE_NAME" ; then
    echo "$dest_dir/$ARCHIVE_NAME" existed:
else
	echo "download source package - $url"

	mkdir -p "$dest_dir"
  cd "$dest_dir"
	curl -L -O "$url"
	if test x$? != x0 ; then
		echo fetch of $ARCHIVE_NAME failed
		exit 1
	fi
fi

if [ ! -e "$dest_dir/$ARCHIVE_NAME" ]; then
    echo "Missing archive $ARCHIVE"
    exit 1
fi

