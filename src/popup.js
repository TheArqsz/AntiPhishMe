  var domain_global;
  var active_scan = false;
  var raport = false;

  function good_change(temp) {
      document.getElementById('result').style.color = '#3dea51';
      document.getElementById('result').innerHTML = temp;
      document.getElementsByClassName('btn_scan')[0].style.background = 'linear-gradient(0deg, rgba(55, 153, 48, 1) 0%, rgba(111, 242, 91, 1) 100%)';
      document.getElementsByTagName('body')[0].style.background = 'linear-gradient(0deg, rgba(66, 113, 63, 1) 0%, rgba(66, 66, 66, 1) 70%)';
      document.getElementById('logo').src = 'img/icon128G.png';
      document.getElementsByClassName('gif')[0].src = 'img/gifg.gif';
      document.getElementById('scan').style.display = 'block';
  }

  function suspicious_change(temp) {
      document.getElementById('result').style.color = '#ee7a2d';
      document.getElementById('result').innerHTML = temp;
      document.getElementsByClassName('btn_scan')[0].style.background = 'linear-gradient(0deg, rgba(255,136,31,1) 0%, rgba(236,172,55,1) 100%)';
      document.getElementsByTagName('body')[0].style.background = 'linear-gradient(0deg, rgba(211,142,63,1) 0%, rgba(66,66,66,1) 100%)';
      document.getElementById('logo').src = 'img/icon128O.png';
      document.getElementsByClassName('gif')[0].src = 'img/gifo.gif';
      document.getElementById('scan').style.display = 'block';
  }

  function malicious_change(temp) {
      document.getElementById('result').style.color = '#ee2d2d';
      document.getElementById('result').innerHTML = temp;
      document.getElementsByClassName('btn_scan')[0].style.background = 'linear-gradient(0deg, rgba(155,49,49,1) 0%, rgba(242,91,91,1) 100%)';
      document.getElementsByTagName('body')[0].style.background = 'linear-gradient(0deg, rgba(147,65,65,1) 0%, rgba(66,66,66,1) 100%)';
      document.getElementById('logo').src = 'img/icon128R.png';
      document.getElementsByClassName('gif')[0].src = 'img/gifr.gif';
      document.getElementById('scan').style.display = 'block';
  }
  chrome.tabs.query({
      active: true,
      lastFocusedWindow: true
  }, tabs => {
      var tab = tabs[0];
      var url = new URL(tab.url)
      if (url.hostname.length > 5) {
          domain_global = url.hostname;
      }
      let domain = {
          url: url.hostname
      }
      document.getElementsByClassName("domain_hostname")[0].innerHTML = domain.url; //wysyla do pliku html ktory wyswietla
      //   chrome.tabs.sendMessage(tab.id, domain.url); //wysyla domene do script.js na klikniecie wtyczki. tab.url zamiast domaiin.url tez dziala
      var verifyall = chrome.runtime.connect({
          name: "verifyall"
      });
      verifyall.postMessage({
          joke: "Knock knock"
      });
      verifyall.onMessage.addListener(function (msg) {
          if (msg.question == "Who's there?")
              verifyall.postMessage({
                  domain: domain.url
              });
          else if (msg.status == 'suspicious') {
              suspicious_change(msg.status);
          } else if (msg.status == 'good') {
              good_change(msg.status);
          } else if (msg.status == 'malicious') {
              malicious_change(msg.status);
          }
      });
      var detailsip = chrome.runtime.connect({
          name: "detailsip"
      });
      detailsip.postMessage({
          wish: "ip"
      });
      detailsip.onMessage.addListener(function (msg) {
          if (msg.question == "url?") {
              detailsip.postMessage({
                  url: domain.url
              });
          } else if (msg.ip === msg.ip) {
              document.getElementsByClassName('ip_domain')[0].innerHTML = msg.ip;
          }
      });
  });

  chrome.runtime.onMessage.addListener(
      (request, sender, sendResponse) => {
          console.log(request)
          if (request.verify == 'suspicious') {
              suspicious_change(request.verify);
          } else if (request.verify == 'good') {
              good_change(request.verify);
          } else if (request.verify == 'malicious') {
              malicious_change(request.verify);
          }
          if (typeof request.ip !== 'undefined') {
              document.getElementsByClassName('ip_domain')[0].innerHTML = request.ip;
          }
      });
  window.onload = function () {
      var dis_btn = document.getElementsByClassName('tile')[0];
      var switcher = chrome.runtime.connect({
          name: "switcher"
      });
      switcher.postMessage({
          status: "status?"
      });
      switcher.onMessage.addListener(function (msg) {
          if (msg.value == true) {
              dis_btn.style.boxShadow = "inset 0px 0px 5px 0px rgba(0, 0, 0, 0.65)";
              document.getElementById('switcher').setAttribute('src', 'img/STOP_pressed.png');
              document.getElementById('active').style.display = "none";
          } else if (msg.value == false) {
              dis_btn.style.boxShadow = "0px 0px 5px 0px rgba(0, 0, 0, 0.65)";
              document.getElementById('switcher').setAttribute('src', 'img/STOP.png');
              document.getElementById('active').style.display = "block";
          }
      })
      document.getElementById('switcher').onclick = function () {
          switcher.postMessage({
              change: "yes"
          });
          switcher.postMessage({
              status: "status?"
          })
          if (dis_btn.style.boxShadow == "rgba(0, 0, 0, 0.65) 0px 0px 5px 0px") {
              dis_btn.style.boxShadow = "inset 0px 0px 5px 0px rgba(0, 0, 0, 0.65)";
              dis_btn.setAttribute('src', 'img/STOP_pressed.png');
              document.getElementById('active').style.display = "none";
          } else {
              dis_btn.style.boxShadow = "0px 0px 5px 0px rgba(0, 0, 0, 0.65)";
              dis_btn.setAttribute('src', 'img/STOP.png');
              document.getElementById('active').style.display = "block";
              chrome.tabs.reload();
          }
      }
      document.getElementsByClassName('btn_scan')[0].onclick = function () {
          document.getElementsByClassName('gif')[0].style.display = 'block';
          document.getElementsByClassName('btn_scan')[0].style.display = 'none';
          var active_scan = true;
          var details = chrome.runtime.connect({
              name: "details"
          });
          details.postMessage({
              want: "some details"
          });
          details.onMessage.addListener(function (msg) {
              if (msg.status == "scanning") {
                  details.postMessage({
                      scan: active_scan,
                      domain: domain_global
                  });
              } else if (msg.href == true) {
                  active_scan = false;
                  raport = true;
              }
          });
      }
      document.getElementById('raport').onclick = function () {
        if(raport == true){
            window.open('raport.html', '_blank');
        }
        else{
            document.getElementsByClassName('btn_scan')[0].click();
        }
      }
  }