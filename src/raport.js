var raport = chrome.runtime.connect({
    name: "raport"
});
raport.postMessage({
    wish: "details"
});
raport.onMessage.addListener(function (msg) {
    if(msg.result == 'yes'){
        if(msg.phishing == 'suspicious'){
            document.getElementsByTagName('link')[0].setAttribute('href', 'img/icon16O.png');
            document.getElementById('logo').setAttribute('src', 'img/logoO.png');
            document.body.style.backgroundImage  = 'url("img/raportO.png")';
        }
        else if(msg.phishing == 'malicious'){
            document.getElementsByTagName('link')[0].setAttribute('href', 'img/icon16R.png');
            document.getElementById('logo').setAttribute('src', 'img/logoR.png');
            document.body.style.backgroundImage  = 'url("img/raportR.png")';
        }
		
		//ip_by_url
		if(msg.ip_by_url == 'none'){
            document.getElementById('ip').innerHTML = 'none';
			document.getElementById('country').innerHTML = 'none';
			document.getElementById('asn').innerHTML = 'none';
        }
        else if(msg.ip_by_url == 'err'){
            document.getElementById('ip').innerHTML = '-';
			document.getElementById('country').innerHTML = '-';
			document.getElementById('asn').innerHTML = '-';
        }
		else{
			document.getElementById('ip').innerHTML = msg.ip_by_url.details.ip;
			document.getElementById('country').innerHTML = msg.ip_by_url.details.country;
			document.getElementById('asn').innerHTML = msg.ip_by_url.details.asn;
		}
		//ip_by_url
		
		//whois
		if(msg.whois == 'none'){
            document.getElementById('creation_date').innerHTML = 'none';
			document.getElementById('company').innerHTML = 'none';
			document.getElementById('organisation').innerHTML = 'none';
			document.getElementById('registration').innerHTML = 'none';
        }
		else if(msg.whois == 'err'){
            document.getElementById('creation_date').innerHTML = '-';
			document.getElementById('company').innerHTML = '-';
			document.getElementById('organisation').innerHTML = '-';
			document.getElementById('registration').innerHTML = '-';
        }
        else{
            document.getElementById('creation_date').innerHTML = msg.whois.details.creation_date.slice(11) + ' ' + msg.whois.details.creation_date.slice(8,10) + '.' + msg.whois.details.creation_date.slice(5,7) + '.' + msg.whois.details.creation_date.slice(0,4);
			document.getElementById('company').innerHTML = (msg.whois.details.name == null) ? 'N/A' : msg.whois.details.name;
			document.getElementById('organisation').innerHTML = (msg.whois.details.org == null) ? 'N/A' : msg.whois.details.org;
			document.getElementById('registration').innerHTML = msg.whois.details.registrar;
        }
		//whois
		
		//domain
			document.getElementById('domain').innerHTML = msg.domain;
        //domain
		
		
        document.getElementById('verify_crtsh').innerHTML = ((msg.verify_crt) != 'err') ? ((msg.verify_crt.status == "good") ? 'Bezpieczna' : 'Niebezpieczna') : "N/A";
        document.getElementById('verify_sfbrowsing').innerHTML = ((msg.verify_sfbrowsing) != 'err') ? ((msg.verify_sfbrowsing.status == "good") ? 'Bezpieczna' : 'Niebezpieczna') : "N/A";
        document.getElementById('verify_urlscan').innerHTML = ((msg.verify_urlscan) != 'err') ? ((msg.verify_urlscan.status == "good") ? 'Bezpieczna' : 'Niebezpieczna') : "N/A";
        document.getElementById('verify_whois').innerHTML = ((msg.verify_whois) != 'err') ? ((msg.verify_whois.status == "good") ? 'Bezpieczna' : 'Niebezpieczna') : "N/A";
        document.getElementById('verify_entropy').innerHTML = ((msg.verify_entropy) != 'err') ? ((msg.verify_entropy.status == "good") ? 'Bezpieczna' : 'Niebezpieczna') : "N/A";
        document.getElementById('verify_cert_hole').innerHTML = ((msg.verify_cert_hole) != 'err') ? ((msg.verify_cert_hole.status == "good") ? 'Bezpieczna' : 'Niebezpieczna') : "N/A";   
        document.getElementById('verify_levenstein').innerHTML = ((msg.verify_levenstein) != 'err') ? ((msg.verify_levenstein.status == "good") ? 'Bezpieczna' : 'Niebezpieczna') : "N/A";
		
		//crtsh
        if(msg.crtsh == 'none' || msg.crtsh == 'err'){
            document.getElementById('crtsh').style.display = 'none';
        }
        else{
            document.getElementById('caid').innerHTML = msg.crtsh.details.caid;
            document.getElementById('ca_register').innerHTML = msg.crtsh.details.registered_at.slice(11,-7) + ' ' + msg.crtsh.details.registered_at.slice(8,10) + '.' + msg.crtsh.details.registered_at.slice(5,7) + '.' + msg.crtsh.details.registered_at.slice(0,4);
            document.getElementById('exhibitor').innerHTML = msg.crtsh.details.issuer.common_name;
            document.getElementById('multi_dns_amount').innerHTML = msg.crtsh.details.multi_dns_amount;
        }
		//crtsh
		
		//urlscan
		if(msg.urlscan == 'err'){
            document.getElementById('server').innerHTML = '-';
			document.getElementById('webapps').innerHTML = '-';
			document.getElementById('no_of_requests').innerHTML = '-';
			document.getElementById('ads_blocked').innerHTML = '-';
			document.getElementById('ipv6_request').innerHTML = '-';
			document.getElementById('https_requests').innerHTML = '-';
			document.getElementById('unique_country_count').innerHTML = '-';
			document.getElementById('country_request').innerHTML = '-';
			document.getElementById('malicious_request').innerHTML = '-';
        }
        else{
           document.getElementById('server').innerHTML = msg.urlscan.details.server;
			document.getElementById('webapps').innerHTML = (msg.urlscan.details.webApps).toString().replace(/['"]+/g, '').replace(/[,]+/g,', ');
			document.getElementById('no_of_requests').innerHTML = msg.urlscan.details.no_of_requests;
			document.getElementById('ads_blocked').innerHTML = msg.urlscan.details.ads_blocked;
			document.getElementById('ipv6_request').innerHTML = msg.urlscan.details.ipv6;
			document.getElementById('https_requests').innerHTML = msg.urlscan.details.https_requests;
			document.getElementById('unique_country_count').innerHTML = msg.urlscan.details.unique_country_count;
			document.getElementById('country_request').innerHTML = (msg.urlscan.details.unique_countries_connected).toString().replace(/['"]+/g, '').replace(/[,]+/g,', ');
			document.getElementById('malicious_request').innerHTML = msg.urlscan.details.malicious_requests;
        }
        //urlscan
		
		//entropy
		if(msg.entropy == 'err'){
		document.getElementById('entropy').innerHTML = '-';
		}
		else{
			document.getElementById('entropy').innerHTML = msg.entropy.details.entropy;
        }
		//entropy
		
		//keywords
		if(msg.keywords == 'err'){
			document.getElementById('matched_keyword').innerHTML = '-';
		}
		else{
			document.getElementById('matched_keyword').innerHTML = msg.keywords;
        }
		//keywords
		
		//levenstein
		if(msg.levenstein == 'err'){
			document.getElementById('levenstein_distance').innerHTML = '-';
		}
		else{
			document.getElementById('levenstein_distance').innerHTML = msg.levenstein;
        }
		//levenstein 
    }
});

window.onload = function () {
    var td_element = document.getElementsByTagName('td');
    for(var i=0; i<td_element.length; i++)
        {
            if(td_element[i].innerText == "Bezpieczna"){
                td_element[i].style.background = "linear-gradient(90deg, rgba(66, 113, 63, 1) 0%, rgba(66, 66, 66, 1) 70%)";
            }
            else if(td_element[i].innerText == "Niebezpieczna"){
                td_element[i].style.background = 'linear-gradient(90deg, rgba(147,65,65,1) 0%, rgba(66,66,66,1) 70%)';
            }
        }
}
