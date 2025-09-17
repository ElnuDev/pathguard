let modal = null;
let modalTitleBar = null;
let modalMessageContainer = null;
let modalOkButton = null;

function makeModal() {
    if (modal) return;
    modal = document.createElement("dialog");
    modal.classList.add("box");
    modalTitleBar = document.createElement("strong");
    modalTitleBar.classList.add("titlebar");
    modal.appendChild(modalTitleBar);
    modalMessageContainer = document.createElement("div")
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

document.body.addEventListener('htmx:beforeSwap', event => {
    console.log(event);
    if (!event.detail.isError) return;
    makeModal();
    modalTitleBar.innerHTML = `Error: ${event.detail.xhr.status} ${event.detail.xhr.statusText}`;
    modal.classList.toggle("bad", true);
    modalMessageContainer.innerHTML = `<p>${event.detail.serverResponse || "Something went wrong."}</p>`;
    modal.showModal();
});

document.addEventListener("htmx:confirm", event => {
    if (!event.detail.question) return;
    event.preventDefault();
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