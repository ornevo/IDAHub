import { createMuiTheme } from '@material-ui/core/styles';

export const MainColor = "#2979ff";
export const CustomMuiTheme = createMuiTheme({
    typography: {
        "fontFamily": "Pontano Sans",
        "fontSize": 14,
        "fontWeightLight": 300,
        "fontWeightRegular": 400,
        "fontWeightMedium": 500,
        h1: { fontFamily: "Dosis" },
        h2: { fontFamily: "Dosis" },
        h3: { fontFamily: "Dosis" },
        h4: { fontFamily: "Dosis" },
        h5: { fontFamily: "Dosis" },
        h6: { fontFamily: "Dosis" },
    },
});