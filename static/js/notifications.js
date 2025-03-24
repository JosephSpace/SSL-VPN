function showNotification(type, message) {
    $.notify(message, {
        style: type,
        autoHide: true,
        clickToHide: true,
        autoHideDelay: 5000,
        className: type,
        position: "top right"
    });
}