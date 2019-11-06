import { createMuiTheme } from '@material-ui/core/styles';

export const JOIN_REQUESTS_UPDATE_INTERVAL = 5000;
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
export const FormsMuiStyle = theme => ({
    '@global': {
      body: {
        backgroundColor: theme.palette.common.white,
      },
    },
    paper: {
      marginTop: theme.spacing(8),
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
    },
    form: {
      width: '100%', // Fix IE 11 issue.
      marginTop: theme.spacing(1),
    },
    submit: {
      margin: theme.spacing(3, 0, 2),
    },
  });
  