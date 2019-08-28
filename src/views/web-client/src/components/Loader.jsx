import React from 'react';
import { BeatLoader } from 'react-spinners';
import { MainColor } from "../shared/Constants";

export default function Loader(props) {
    return (
        <BeatLoader loading={true}
            sizeUnit={"px"}
            size={10}
            style={{marginTop: "100px"}}
            color={ MainColor }/>
    );
}
