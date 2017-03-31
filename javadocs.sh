#!/bin/bash

if [ "$1" = "docs" ]; then
    mvn javadoc:javadoc
    exit
elif [ "$1" = "site" ]; then
    echo "Checking for changes."
    git status
    if ! git diff-index --quiet HEAD --; then
        echo "There are uncommitted changes"
        exit 1
    fi
    rm -rf target/site
    mvn javadoc:javadoc
    cp README.md target/

    git checkout gh-pages
    cp -r target/site/apidocs .
    cp target/README.md .

    git add apidocs/*
    git commit -a -m "update pages"
    git push
    git checkout master
    exit   
elif [ -z "$1" ]; then 
    echo Usage: $0 target
    echo where target is:
else
    echo Unknown target: "$1"
    echo Valid targets are:
fi

echo "  docs       Generates javadoc"
echo "  site       Generates javadoc and push to GitHub Pages"
