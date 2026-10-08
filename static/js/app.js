function getToken() {
    return localStorage.getItem("access_token");
}

function setToken(token) {
    localStorage.setItem("access_token", token);
}

function removeToken() {
    localStorage.removeItem("access_token");
}


async function login(email, password) {

    const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            email: email,
            password: password
        })
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            data.error || "Login failed."
        );
    }

    setToken(data.access_token);

    return data;
}


async function getCurrentUser() {

    const token = getToken();

    if (!token) {
        return null;
    }

    const response = await fetch("/api/auth/me", {
        headers: {
            "Authorization": `Bearer ${token}`
        }
    });

    if (!response.ok) {
        removeToken();
        return null;
    }

    const data = await response.json();

    return data.user;
}


function logout() {

    removeToken();

    window.location.href = "/login";
}


document.addEventListener("DOMContentLoaded", () => {

    const loginForm = document.getElementById("login-form");

    if (!loginForm) {
        return;
    }

    loginForm.addEventListener("submit", async (event) => {

        event.preventDefault();

        const email =
            document.getElementById("email").value.trim();

        const password =
            document.getElementById("password").value;

        const errorElement =
            document.getElementById("login-error");

        errorElement.classList.add("hidden");
        errorElement.textContent = "";

        try {

            await login(
                email,
                password
            );

            window.location.href = "/dashboard";

        } catch (error) {

            errorElement.textContent =
                error.message;

            errorElement.classList.remove("hidden");
        }

    });

});