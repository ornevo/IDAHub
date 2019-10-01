import React from 'react';
import BackVideo from "../res/cyberBackVideo.webm";


const VID_WIDTH = 1368;
const VID_HEIGHT = 1320;


export default class BackgroundCyberVideo extends React.Component {
    constructor(props) {
        super(props);
        this.state = this.getUpToDateState();
    }

    // up to date considering current windowsize
    getUpToDateState() {
        const screenWidth = Math.max(document.documentElement.clientWidth, window.innerWidth || 0);
        const screenHeight = Math.max(document.documentElement.clientHeight, window.innerHeight || 0);
            
        return { screenWidth, screenHeight };
    }

    // To dynamically change modal size to screen size, we track resize events
    // We assume only one modal at a time "lives"
    componentDidMount() {
        window.addEventListener("resize", this.handleResize.bind(this));
    }

    handleResize() {
        this.setState(this.getUpToDateState());
    }

    render() {
        const cols = Math.ceil(this.state.screenWidth / VID_WIDTH);
        const rows = Math.ceil(this.state.screenHeight / VID_HEIGHT);

        var locations = [];
        for (let rowi = 0; rowi < rows; rowi++)
            for (let coli = 0; coli < cols; coli++)
                locations.push([VID_WIDTH * coli, VID_HEIGHT * rowi])

        return (
            <span>
            {
                locations.map(([x, y]) => (
                    <video key={x.toString() + "," + y.toString()} muted autoPlay loop className="Full-screen-backvideo" style={{left: x + "px", top: y + "px"}}>
                        <source src={BackVideo} autoPlay="" loop="" type="video/mp4" />
                    </video>
                ))
            }
            </span>
        );
    }

}