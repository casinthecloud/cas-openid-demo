package org.leleuj;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.openid4java.association.AssociationException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;
import org.openid4java.message.sreg.SRegRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class MainController {

    private static final Logger logger = LoggerFactory.getLogger(MainController.class);

    private static final String DISCOVERED = "discovered";

    private static final String EXTENSION = ".html";

    private static final String OPENID_CALLBACK = "openId" + EXTENSION;

    private static ConsumerManager manager;

    static {
        manager = new ConsumerManager();
    }

    @RequestMapping("/home")
    public String home() {
        return "home";
    }

    @RequestMapping("/confirm")
    public String confirm(@RequestParam("userid") String userid, final HttpServletRequest request,
                          final HttpSession session) {
        logger.debug("userid: {}", userid);
        try {
            List<DiscoveryInformation> discoveries = manager.discover(userid);
            DiscoveryInformation discovered = manager.associate(discoveries);
            logger.debug("discovered: {}", discovered);
            logger.debug("discovered.version: {}", discovered.getVersion());
            session.setAttribute(DISCOVERED, discovered);
            String openIdCallbackUrl = request.getRequestURL().toString().replaceAll("confirm" + EXTENSION, "")
                                       + OPENID_CALLBACK;
            logger.debug("openIdCallbackUrl: {}", openIdCallbackUrl);
            AuthRequest authRequest = manager.authenticate(discovered, openIdCallbackUrl);
            //authRequest.setIdentity("http://specs.openid.net/auth/2.0/identifier_select");
            //authRequest.setClaimed("http://specs.openid.net/auth/2.0/identifier_select");
            SRegRequest sRegRequest = SRegRequest.createFetchRequest();
            sRegRequest.addAttribute("email", false);
            sRegRequest.addAttribute("fullname", false);
            sRegRequest.addAttribute("dob", false);
            sRegRequest.addAttribute("postcode", false);
            authRequest.addExtension(sRegRequest);
            String openIdUrl = authRequest.getDestinationUrl(true);
            logger.debug("openIdUrl: {}", openIdUrl);
            return "redirect:" + openIdUrl;
        } catch (DiscoveryException e) {
            logger.error("discovery exception", e);
            return "home";
        } catch (ConsumerException e) {
            logger.error("consumer exception", e);
            return "home";
        } catch (MessageException e) {
            logger.error("message exception", e);
            return "home";
        }
    }

    @RequestMapping("/openId")
    public String openId(final HttpServletRequest request, final HttpSession session) {
        ParameterList openidResp = new ParameterList(request.getParameterMap());
        DiscoveryInformation discovered = (DiscoveryInformation) session.getAttribute(DISCOVERED);

        StringBuffer receivingURL = request.getRequestURL();
        String queryString = request.getQueryString();
        if (queryString != null && queryString.length() > 0) {
            receivingURL.append("?").append(request.getQueryString());
        }
        logger.debug("receivingURL: {}", receivingURL);
        VerificationResult verification = null;
        try {
            verification = manager.verify(receivingURL.toString(), openidResp, discovered);
        } catch (MessageException e) {
            logger.error("message exception", e);
            return "home";
        } catch (DiscoveryException e) {
            logger.error("discovery exception", e);
            return "home";
        } catch (AssociationException e) {
            logger.error("association exception", e);
            return "home";
        }

        logger.debug("verification: {}", verification);
        if (verification != null) {
            Identifier verified = verification.getVerifiedId();
            logger.debug("verified: {}", verified);
            if (verified != null) {
                return "success";
            }
        }

        return "home";
    }
}
