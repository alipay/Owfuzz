#! /bin/bash


function ie_creator(){
	for ((i=0; i<256; ++i))  
	do  
	    echo -e "    ies_creator["$i"].id = "$i";" >> ies_creator.c
	    echo -e "    ies_creator["$i"].pf_ie_creator = ie_"$i"_creator;" >> ies_creator.c
	    echo -e "" >> ies_creator.c
	done	
}


ie_creator

