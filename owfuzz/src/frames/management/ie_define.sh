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
            local ie_sub=${file##*ie_}
            local ie_num=${ie_sub%%_*}
            local id_def1=`xrsh_toupper $ie_define`
            echo "#define "$id_def1" "$ie_num >> ieee80211_ie.h

        fi
    done
}


rm ieee80211_ie.h
echo -e "#ifndef IEEE80211_IE_H" >> ieee80211_ie.h
echo -e "#define IEEE80211_IE_H" >> ieee80211_ie.h
echo -e "" >> ieee80211_ie.h
read_dir ./ies
echo -e "" >> ieee80211_ie.h
echo -e "#endif" >> ieee80211_ie.h