#! /bin/bash

function xrsh_toupper()
{
    echo $1 | tr 'a-z' 'A-Z'
}


function read_dir(){
    for file in `ls $1`
    do
        if [ -d $1"/"$file ]
        then
            echo $1"/"$file
        else
            local ie_define=${file%.h*}
            local id_def1=`xrsh_toupper $ie_define"_h"`
            echo "" > $1"/"$file
            echo -e "#ifndef "$id_def1 >> $1"/"$file
            echo -e "#define "$id_def1 >> $1"/"$file
            echo -e "" >> $1"/"$file
            echo -e "#include \"../ies_common.h\"" >> $1"/"$file
            echo -e "" >> $1"/"$file
            echo -e "" >> $1"/"$file
            echo -e "#endif" >> $1"/"$file

            echo -e "#include \""$ie_define".h\"" > "./iesc/"$ie_define".c"

        fi
    done
}

rm -rf iesc
mkdir iesc
read_dir ./ies
