#! /bin/bash
function read_dir(){
    for file in `ls $1`
    do
        if [ -d $1"/"$file ]
        then
            echo $1"/"$file
        else
            echo "#include \"./ies/"$file"\"" >> ./ies.h
        fi
    done
}

rm ./ies.h
echo -e "#ifndef IES_H" >> ./ies.h
echo -e "#define IES_H" >> ./ies.h
echo -e "" >> ./ies.h
echo -e "#include <stdlib.h>" >> ./ies.h
echo -e "#include <unistd.h>" >> ./ies.h
echo -e "#include <time.h>" >> ./ies.h
echo -e "#include <assert.h>" >> ./ies.h
echo -e "#include <string.h>" >> ./ies.h
echo -e "#include \"ieee80211_ie.h\"" >> ./ies.h
read_dir ./ies
echo -e "" >> ./ies.h
echo -e "#endif" >> ./ies.h