let modal;
let modalTitleBar;
let modalMessageContainer;
let modalOkButton;
let shiftPressed = false;

function toggleShift(pressed) {
    shiftPressed = pressed;
    document.body.classList.toggle("shift", shiftPressed);
}

document.addEventListener("keydown", event => { if (event.key === "Shift") toggleShift(true) });
document.addEventListener("keyup", event => { if (event.key === "Shift") toggleShift(false) });

function makeModal() {
    if (typeof modal !== "undefined") {
        if (!modal.isConnected) document.body.appendChild(modal);
        return;
    }
    modal = document.createElement("dialog");
    modal.classList.add("box");
    modalTitleBar = document.createElement("strong");
    modalTitleBar.classList.add("titlebar");
    modal.appendChild(modalTitleBar);
    modalMessageContainer = document.createElement("div");
    modal.appendChild(modalMessageContainer);
    const form = document.createElement("form");
    form.method = "dialog";
    modalOkButton = document.createElement("button");
    modalOkButton.innerHTML = "Cancel";
    modalOkButton.classList.add("float:right");
    form.append(modalOkButton);
    modal.appendChild(form);
    document.body.appendChild(modal);
}

document.addEventListener("DOMContentLoaded", _event => {
    function openHash() {
        try {
            const target = document.querySelector(window.location.hash);
            if (target === null) return;
            if (target.tagName === "DETAILS") target.setAttribute("open", "");
        } catch {}
    }
    openHash();

    document.body.addEventListener("htmx:afterSwap", event => {
        // https://github.com/bigskysoftware/htmx/issues/3447
        if (!event.detail.boosted) return;
        const hash = event.detail.pathInfo.requestPath.split("#")[1];
        if (hash === undefined) return;
        window.location.hash = event.detail.pathInfo.requestPath.split("#")[1];
        openHash();
    });

    document.body.addEventListener("htmx:beforeSwap", event => {
        if (!event.detail.isError) return;
        if (event.detail.boosted) {
            event.detail.shouldSwap = true;
            event.detail.isError = false;
            return;
        }
        makeModal();
        modalTitleBar.innerHTML = `Error: ${event.detail.xhr.status} ${event.detail.xhr.statusText}`;
        modal.classList.toggle("bad", true);
        modalMessageContainer.innerHTML = `<p>${event.detail.serverResponse || "Something went wrong."}</p>`;
        modal.showModal();
    });

    document.addEventListener("htmx:confirm", event => {
        if (!event.detail.question) return;
        event.preventDefault();
        if (shiftPressed) {
            event.detail.issueRequest(true);
            return;
        }
        makeModal();
        modalTitleBar.innerHTML = "Confirmation";
        modal.classList.toggle("bad", false);
        modalMessageContainer.innerHTML = `<p>${event.detail.question}</p>`;
        const confirmButton = document.createElement("button");
        confirmButton.classList.add("float:right");
        confirmButton.style.marginLeft = "1ch";
        confirmButton.innerHTML = "Confirm";
        confirmButton.onclick = () => {
            modal.close();
            event.detail.issueRequest(true);
        };
        modalMessageContainer.appendChild(confirmButton);
        modal.showModal();
        modalOkButton.focus();
    });
});

/**
 * @param {HTMLElement} element Element to swap
 */
function swapUp(element) {
    element.parentElement.insertBefore(element, element.previousSibling);
}

/**
 * @param {HTMLElement} element Element to swap
 */
function swapDown(element) {
    element.parentElement.insertBefore(element.nextSibling, element);
}