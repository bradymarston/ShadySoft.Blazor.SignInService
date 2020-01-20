window.shadyAuthHelpers = {
    login: (loginModel, callbackObject) => {
        var xhr = new XMLHttpRequest();
        xhr.open("POST", '/api/shadyauth/login?encodedLoginModel=' + loginModel, true);

        //Send the proper header information along with the request
        xhr.setRequestHeader("Content-Type", "application/json");

        xhr.onreadystatechange = function () { // Call a function when the state changes.
            if (this.readyState === XMLHttpRequest.DONE) {
                callbackObject.invokeMethodAsync('ClientLoginComplete', this.responseText);
            }
        };

        xhr.send();
    }
};
