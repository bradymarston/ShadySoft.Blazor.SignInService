window.shadyAuthHelpers = {
    login: (loginModel, callbackObject) => {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", '/api/shadyauth/login?encodedLoginModel=' + loginModel, true);

        //Send the proper header information along with the request
        xhr.setRequestHeader("Content-Type", "application/json");

        xhr.onreadystatechange = function () { // Call a function when the state changes.
            if (this.readyState === XMLHttpRequest.DONE) {
                callbackObject.invokeMethodAsync('ClientSignInComplete', this.responseText);
            }
        };

        xhr.send();
    },

    logout: (callbackObject) => {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", '/api/shadyauth/logout', true);
        xhr.responseType = 'text';

        xhr.onreadystatechange = function () { // Call a function when the state changes.
            if (this.readyState === XMLHttpRequest.DONE) {
                callbackObject.invokeMethodAsync('ClientSignOutComplete');
            }
        };

        xhr.send();
    },

    refresh: (refreshInfo, callbackObject) => {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", '/api/shadyauth/refresh?encodedRefeshDto=' + refreshInfo, true);
        xhr.responseType = 'text';

        //Send the proper header information along with the request
        xhr.setRequestHeader("Content-Type", "application/json");

        xhr.onreadystatechange = function () { // Call a function when the state changes.
            if (this.readyState === XMLHttpRequest.DONE) {
                callbackObject.invokeMethodAsync('ClientRefreshSignInComplete', this.status === 200);
            }
        };

        xhr.send();
    }
};
