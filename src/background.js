var table_address = new Array();
var table_ip = new Array();
var table_urlscan = new Array();
var table_crtsh = new Array();
var table_entropy = new Array();
var table_ip_by_url = new Array();
var table_keywords = new Array();
var table_levenstein = new Array();
var table_whois = new Array();
var verify_cert_hole = new Array();
var verify_crt = new Array();
var verify_entropy = new Array();
var verify_keywords = new Array();
var verify_levenstein = new Array();
var verify_sfbrowsing = new Array();
var verify_urlscan = new Array();
var verify_whois = new Array();
var all_details = {};
var scan_crtsh = false; //href = 0
var scan_urlscan = false; //href = 1
var scan_entropy = false; //href = 2
var scan_ip_by_url = false; //href = 3
var scan_keywords = false; //href = 4
var scan_levenstein = false; //href = 5
var scan_safebrowsing = false; //href = 6
var scan_whois = false; //href = 7
var scan_verify = false;
var scan_verify_cert_hole = false;
var scan_verify_crt = false;
var scan_verify_entropy = false;
var scan_verify_keywords = false;
var scan_verify_levenstein = false;
var scan_verify_sfbrowsing = false;
var scan_verify_urlscan = false;
var scan_verify_whois = false;
var scan_ip = false;
var active_href = false;
var href = [false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
var disable = false;


chrome.runtime.onConnect.addListener(function (switcher) {
    switcher.onMessage.addListener(function (msg) {
        if (msg.status == "status?") {
            switcher.postMessage({
                value: disable
            });
        } else if (msg.change == "yes") {
            disable = !disable
        }
    });
});

chrome.runtime.onMessage.addListener(
    (request, sender, sendResponse) => {
        if (request.message === request.message) {
            function icon_change() {
                if (table_address[request.message] == 'suspicious') {
                    chrome.browserAction.setIcon({
                        path: "img/icon32O.png",
                        tabId: sender.tab.id
                    });
                } else if (table_address[request.message] == 'malicious') {
                    chrome.browserAction.setIcon({
                        path: "img/icon32R.png",
                        tabId: sender.tab.id
                    });
                } else if (table_address[request.message] == 'good') {
                    chrome.browserAction.setIcon({
                        path: "img/icon32G.png",
                        tabId: sender.tab.id
                    });
                }
            }
            let domain = {
                "url": request.message
            }
            icon_change();
            if ((typeof table_address[request.message] === 'undefined') && (disable == false)) {
                console.log("baza pusta, skanuje verify - " + scan_verify);
                if (scan_verify == false) {
                    scan_verify = true;
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/verify/all",
                        data: JSON.stringify(domain),
                        success: VerifyAll,
						error: function () {
                            scan_verify = false;
							table_address[msg.domain] = 'err';
                        }
                    });

                    function VerifyAll(data) {
                        table_address[request.message] = data.status;
                        scan_verify = false;
                        chrome.runtime.sendMessage({
                            verify: table_address[request.message]
                        });
                        icon_change();
                    }
                }
            }
            if ((typeof table_ip[request.message] === 'undefined') && (disable == false)) {
                console.log("baza pusta, skanuje ip - " + scan_verify);
                if (scan_ip == false) {
                    scan_ip = true;
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/details/ip_by_url",
                        data: JSON.stringify(domain),
                        success: DomainIP,
                        error: function () {
                            scan_ip = false;
							table_ip[msg.domain] = 'err';
                        }
                    });

                    function DomainIP(data) {
                        table_ip[request.message] = data.details.ip;
                        scan_ip = false;
                        chrome.runtime.sendMessage({
                            ip: table_ip[request.message]
                        });
                    }
                }
            }
        }
    });

chrome.runtime.onConnect.addListener(function (verifyall) {
    // console.assert(verifyall.name == "knockknock");
    verifyall.onMessage.addListener(function (msg) {
        if (msg.joke == "Knock knock")
            verifyall.postMessage({
                question: "Who's there?"
            });
        else if (msg.domain === msg.domain) {
            verifyall.postMessage({
                status: table_address[msg.domain]
            });
        }
    });
});
chrome.runtime.onConnect.addListener(function (detailsip) {
    // console.assert(detailsip.name == "detailsip");
    detailsip.onMessage.addListener(function (msg) {
        if (msg.wish == "ip")
            detailsip.postMessage({
                question: "url?"
            });
        else if (msg.url === msg.url) {
            detailsip.postMessage({
                ip: table_ip[msg.url]
            });
        }
    });
});
chrome.runtime.onConnect.addListener(function (details) {
    // console.assert(details.name == "details");
    details.onMessage.addListener(function (msg) {
        if (msg.want == "some details")
            details.postMessage({
                status: "scanning"
            });
        else if (msg.scan == true) {
            if (typeof table_crtsh[msg.domain] === 'undefined') {
                console.log("baza csrth pusta, skanuje details - " + scan_crtsh);
                if (scan_crtsh == false) {
                    scan_crtsh = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/details/crtsh",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            table_crtsh[msg.domain] = data;
                            scan_crtsh = false;
                            href[0] = true;
                        },
                        statusCode: {
                            202: function () {
                                scan_crtsh = false;
                                table_crtsh[msg.domain] = 'none';
                                href[0] = true;
                            }
                        },
                        error: function () {
                            scan_crtsh = false;
							table_crtsh[msg.domain] = 'err';
                            href[0] = true;
                        }
                    });
                }
            } else {
                if (href[0] != true) {
                    href[0] = true;
                }
            }
            if (typeof table_urlscan[msg.domain] === 'undefined') {
                console.log("baza urlscan pusta, skanuje details - " + scan_urlscan);
                if (scan_urlscan == false) {
                    scan_urlscan = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/details/urlscan",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            table_urlscan[msg.domain] = data;
                            scan_urlscan = false;
                            href[1] = true;
                        },
                        error: function () {
                            scan_urlscan = false;
							table_urlscan[msg.domain] = 'err';
                            href[1] = true;
                        }
                    });
                }
            } else {
                if (href[1] != true) {
                    href[1] = true;
                }
            }
            if (typeof table_entropy[msg.domain] === 'undefined') {
                console.log("baza entropy pusta, skanuje details - " + scan_entropy);
                if (scan_entropy == false) {
                    scan_entropy = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/details/entropy",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            table_entropy[msg.domain] = data;
                            scan_entropy = false;
                            href[2] = true;
                        },
                        error: function () {
                            scan_entropy = false;
							table_entropy[msg.domain] = 'err';
                            href[2] = true;
                        }
                    });
                }
            } else {
                if (href[2] != true) {
                    href[2] = true;
                }
            }
            if (typeof table_ip_by_url[msg.domain] === 'undefined') {
                console.log("baza ip_by_url pusta, skanuje details - " + scan_ip_by_url);
                if (scan_ip_by_url == false) {
                    scan_ip_by_url = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/details/ip_by_url",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            table_ip_by_url[msg.domain] = data;
                            scan_ip_by_url = false;
                            href[3] = true;
                        },
						statusCode: {
                            202: function () {
                                scan_ip_by_url = false;
                                table_ip_by_url[msg.domain] = 'none';
                                href[3] = true;
                            }
                        },
                        error: function () {
                            scan_ip_by_url = false;
							table_ip_by_url[msg.domain] = 'err';
                            href[3] = true;
                        }
                    });
                }
            } else {
                if (href[3] != true) {
                    href[3] = true;
                }
            }
            if (typeof table_keywords[msg.domain] === 'undefined') {
                console.log("baza keywords pusta, skanuje details - " + scan_keywords);
                if (scan_keywords == false) {
                    scan_keywords = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/details/keywords",
                        data: JSON.stringify(domain),
                        success: function (data, xhr) {
                            table_keywords[msg.domain] = data;
                            scan_keywords = false;
                            href[4] = true;
                        },
                        statusCode: {
                            200: function () {
                                table_keywords[msg.domain] = JSON.stringify(table_keywords[msg.domain].details.matched_keyword);
                            },
                            202: function () {
                                table_keywords[msg.domain] = '0';
                            }
                        },
                        error: function () {
                            scan_keywords = false;
							table_keywords[msg.domain] = 'err';
                            href[4] = true;
                        }
                    });
                }
            } else {
                if (href[4] != true) {
                    href[4] = true;
                }
            }
            if (typeof table_levenstein[msg.domain] === 'undefined') {
                console.log("baza levenstein pusta, skanuje details - " + scan_levenstein);
                if (scan_levenstein == false) {
                    scan_levenstein = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/details/levenstein",
                        data: JSON.stringify(domain),
                        success: function (data, xhr) {
                            table_levenstein[msg.domain] = data;
                            scan_levenstein = false;
                            href[5] = true;
                        },
                        statusCode: {
                            200: function () {
                                table_levenstein[msg.domain] = JSON.stringify(table_levenstein[msg.domain].details.levenstein_distance);
                            },
                            202: function () {
                                table_levenstein[msg.domain] = '0';
                            }
                        },
                        error: function () {
                            scan_levenstein = false;
							table_levenstein[msg.domain] = 'err';
                            href[5] = true;
                        }
                    });
                }
            } else {
                if (href[5] != true) {
                    href[5] = true;
                }
            }
            if (typeof table_whois[msg.domain] === 'undefined') {
                console.log("baza whois pusta, skanuje details - " + scan_whois);
                if (scan_whois == false) {
                    scan_whois = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/details/whois",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            table_whois[msg.domain] = data;
                            scan_whois = false;
                            href[6] = true;
                        },
						statusCode: {
                            202: function () {
                                scan_whois = false;
                                table_whois[msg.domain] = 'none';
                                href[6] = true;
                            }
                        },
                        error: function () {
                            scan_whois = false;
							table_whois[msg.domain] = 'err';
                            href[6] = true;
                        }
                    });
                }
            } else {
                if (href[6] != true) {
                    href[6] = true;
                }
            }
            if (typeof verify_cert_hole[msg.domain] === 'undefined') {
                console.log("baza verify_cert_hole pusta, skanuje details - " + scan_verify_cert_hole);
                if (scan_verify_cert_hole == false) {
                    scan_verify_cert_hole = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/verify/by_cert_hole",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            verify_cert_hole[msg.domain] = data;
                            scan_verify_cert_hole = false;
                            href[7] = true;
                        },
                        error: function () {
                            scan_verify_cert_hole = false;
							verify_cert_hole[msg.domain] = 'err';
                            href[7] = true;
                        }
                    });
                }
            } else {
                if (href[7] != true) {
                    href[7] = true;
                }
            }
            if (typeof verify_crt[msg.domain] === 'undefined') {
                console.log("baza verify_crt pusta, skanuje details - " + scan_verify_crt);
                if (scan_verify_crt == false) {
                    scan_verify_crt = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/verify/by_crt",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            verify_crt[msg.domain] = data;
                            scan_verify_crt = false;
                            href[8] = true;
                        },
                        error: function () {
                            scan_verify_crt = false;
							verify_crt[msg.domain] = 'err';
                            href[8] = true;
                        }
                    });
                }
            } else {
                if (href[8] != true) {
                    href[8] = true;
                }
            }
            if (typeof verify_entropy[msg.domain] === 'undefined') {
                console.log("baza verify_entropy pusta, skanuje details - " + scan_verify_entropy);
                if (scan_verify_entropy == false) {
                    scan_verify_entropy = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/verify/by_entropy",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            verify_entropy[msg.domain] = data;
                            scan_verify_entropy = false;
                            href[9] = true;
                        },
                        error: function () {
                            scan_verify_entropy = false;
							verify_entropy[msg.domain] = 'err';
                            href[9] = true;
                        }
                    });
                }
            } else {
                if (href[9] != true) {
                    href[9] = true;
                }
            }
            if (typeof verify_keywords[msg.domain] === 'undefined') {
                console.log("baza verify_keywords pusta, skanuje details - " + scan_verify_keywords);
                if (scan_verify_keywords == false) {
                    scan_verify_keywords = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/verify/by_keywords",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            verify_keywords[msg.domain] = data;
                            scan_verify_keywords = false;
                            href[10] = true;
                        },
                        error: function () {
                            scan_verify_keywords = false;
							verify_keywords[msg.domain] = 'err';
                            href[10] = true;
                        }
                    });
                }
            } else {
                if (href[10] != true) {
                    href[10] = true;
                }
            }
            if (typeof verify_levenstein[msg.domain] === 'undefined') {
                console.log("baza verify_levenstein pusta, skanuje details - " + scan_verify_levenstein);
                if (scan_verify_levenstein == false) {
                    scan_verify_levenstein = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/verify/by_levenstein",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            verify_levenstein[msg.domain] = data;
                            scan_verify_levenstein = false;
                            href[11] = true;
                        },
                        error: function () {
                            scan_verify_levenstein = false;
							verify_levenstein[msg.domain] = 'err';
                            href[11] = true;
                        }
                    });
                }
            } else {
                if (href[11] != true) {
                    href[11] = true;
                }
            }
            if (typeof verify_sfbrowsing[msg.domain] === 'undefined') {
                console.log("baza verify_sfbrowsing pusta, skanuje details - " + scan_verify_sfbrowsing);
                if (scan_verify_sfbrowsing == false) {
                    scan_verify_sfbrowsing = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/verify/by_sfbrowsing",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            verify_sfbrowsing[msg.domain] = data;
                            scan_verify_sfbrowsing = false;
                            href[12] = true;
                        },
                        error: function () {
                            scan_verify_sfbrowsing = false;
							verify_sfbrowsing[msg.domain] = 'err';
                            href[12] = true;
                        }
                    });
                }
            } else {
                if (href[12] != true) {
                    href[12] = true;
                }
            }
            if (typeof verify_urlscan[msg.domain] === 'undefined') {
                console.log("baza verify_urlscan pusta, skanuje details - " + scan_verify_urlscan);
                if (scan_verify_urlscan == false) {
                    scan_verify_urlscan = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/verify/by_urlscan",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            verify_urlscan[msg.domain] = data;
                            scan_verify_urlscan = false;
                            href[13] = true;
                        },
                        error: function () {
                            scan_verify_urlscan = false;
							verify_urlscan[msg.domain] = 'err';
                            href[13] = true;
                        }
                    });
                }
            } else {
                if (href[13] != true) {
                    href[13] = true;
                }
            }
            if (typeof verify_whois[msg.domain] === 'undefined') {
                console.log("baza verify_whois pusta, skanuje details - " + scan_verify_whois);
                if (scan_verify_whois == false) {
                    scan_verify_whois = true;
                    let domain = {
                        "url": msg.domain
                    }
                    $.ajax({
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        type: "POST",
                        url: "http://{url}/verify/by_whois",
                        data: JSON.stringify(domain),
                        success: function (data) {
                            verify_whois[msg.domain] = data;
                            scan_verify_whois = false;
                            href[14] = true;
                        },
                        error: function () {
                            scan_verify_whois = false;
							verify_whois[msg.domain] = 'err';
                            href[14] = true;
                        }
                    });
                }
            } else {
                if (href[14] != true) {
                    href[14] = true;
                }
            }

            function check_table(i) {
                return i == true;
            }
            if (href.every(check_table)) {
                all_details[0] = table_address[msg.domain];
                all_details[1] = table_crtsh[msg.domain];
                all_details[2] = table_urlscan[msg.domain];
                all_details[3] = table_entropy[msg.domain];
                all_details[4] = table_ip_by_url[msg.domain];
                all_details[5] = table_keywords[msg.domain];
                all_details[6] = table_levenstein[msg.domain];
                all_details[7] = table_whois[msg.domain];
                all_details[8] = verify_cert_hole[msg.domain];
                all_details[9] = verify_crt[msg.domain];
                all_details[10] = verify_entropy[msg.domain];
                all_details[11] = verify_keywords[msg.domain];
                all_details[12] = verify_levenstein[msg.domain];
                all_details[13] = verify_sfbrowsing[msg.domain];
                all_details[14] = verify_urlscan[msg.domain];
                all_details[15] = verify_whois[msg.domain];
                all_details[16] = msg.domain;
                active_href = true;
                details.postMessage({
                    href: active_href
                });
                active_href = false;
                href = [false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
				window.open('raport.html', '_blank');
            } else {
                details.postMessage({
                    status: "scanning"
                });
            }
        }

    });
});
chrome.runtime.onConnect.addListener(function (raport) {
    // console.assert(raport.name == "details");
    raport.onMessage.addListener(function (msg) {
        if (msg.wish == "details") {
            raport.postMessage({
                result: 'yes',
                phishing: all_details[0],
                crtsh: all_details[1],
                urlscan: all_details[2],
                entropy: all_details[3],
                ip_by_url: all_details[4],
                keywords: all_details[5],
                levenstein: all_details[6],
                whois: all_details[7],
                verify_cert_hole: all_details[8],
                verify_crt: all_details[9],
                verify_entropy: all_details[10],
                verify_keywords: all_details[11],
                verify_levenstein: all_details[12],
                verify_sfbrowsing: all_details[13],
                verify_urlscan: all_details[14],
                verify_whois: all_details[15],
                domain: all_details[16]
            })
        }
    });
});