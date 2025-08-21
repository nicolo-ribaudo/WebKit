/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 * Copyright (C) 2013-2025 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "MixedContentChecker.h"

#include "BlobURL.h"
#include "Document.h"
#include "LegacySchemeRegistry.h"
#include "LocalFrame.h"
#include "SecurityOrigin.h"
#include <JavaScriptCore/ConsoleTypes.h>
#include <wtf/text/MakeString.h>

namespace WebCore {

static bool isNonLocalHostPotentiallyTrustworthyURL(const URL& url)
{
    if (!url.isValid()) return true;

    // Secure Contexts
    // W3C Candidate Recommendation Draft, 10 November 2023
    // 3.2. Is url potentially trustworthy?

    // We currently deviate from the mixed content spec, and do not consider localhost
    // or loopback URLs as secure contexts if they do not use a secure scheme.
    // https://bugs.webkit.org/show_bug.cgi?id=171934
    if (SecurityOrigin::isLocalHostOrLoopbackIPAddress(url.host()))
        return LegacySchemeRegistry::shouldTreatURLSchemeAsSecure(url.protocol());

    // 2. If url’s scheme is "data", return "Potentially Trustworthy".
    if (url.protocolIsData())
        return true;

    // 3. Return the result of executing § 3.1 Is origin potentially trustworthy? on url’s origin.
    // NOTE: The origin of blob: URLs is the origin of the context in which they were created.
    //       Therefore, blobs created in a trustworthy origin will themselves be potentially
    //       trustworthy.
    if (url.protocolIsBlob()) {
        RefPtr origin = SecurityOrigin::createForBlobURL(url);

        // We currently deviate from the mixed content spec, and do not consider localhost
        // or loopback URLs as secure contexts if they do not use a secure scheme.
        // https://bugs.webkit.org/show_bug.cgi?id=171934
        if (SecurityOrigin::isLocalHostOrLoopbackIPAddress(origin->host()))
            return LegacySchemeRegistry::shouldTreatURLSchemeAsSecure(origin->protocol());

        return origin->isPotentiallyTrustworthy();
    }
    return shouldTreatAsPotentiallyTrustworthy(url);
}

static bool hasNonLocalHostPotentiallyTrustworthyOrigin(const Document& document)
{
    auto& origin = document.securityOrigin();

    // We currently deviate from the mixed content spec, and do not consider localhost
    // or loopback URLs as secure contexts if they do not use a secure scheme.
    // https://bugs.webkit.org/show_bug.cgi?id=171934
    if (SecurityOrigin::isLocalHostOrLoopbackIPAddress(origin.host()))
        return LegacySchemeRegistry::shouldTreatURLSchemeAsSecure(origin.protocol());

    // sandboxed iframes have an opaque origin so we should perform the mixed content
    // check considering the origin the iframe would have had if it were not sandboxed.
    if (origin.isOpaque())
        return !document.url().protocolIsData() && isNonLocalHostPotentiallyTrustworthyURL(document.url());

    return origin.isPotentiallyTrustworthy();
}

static bool dataContextProhibitsMixedSecurityContexts(const LocalFrame& frame)
{
    RefPtr document = frame.document();

    while (document) {
        if (hasNonLocalHostPotentiallyTrustworthyOrigin(*document))
            return true;

        RefPtr frame = document->frame();
        if (!frame || frame->isMainFrame())
            break;

        RefPtr parentFrame = frame->tree().parent();
        if (!parentFrame)
            break;

        if (RefPtr localParentFrame = dynamicDowncast<LocalFrame>(parentFrame.get()))
            document = localParentFrame->document();
        else {
            // FIXME: <rdar://116259764> Make mixed content checks work correctly with site isolated iframes.
            break;
        }
    }

    return false;
}

static bool prohibitsMixedSecurityContexts(const Document& document)
{
    // https://www.w3.org/TR/mixed-content/#upgrade-algorithm
    // Editor’s Draft, 23 February 2023
    // 4.3. Does settings prohibit mixed security contexts?

    return hasNonLocalHostPotentiallyTrustworthyOrigin(document) || (document.url().protocolIsData() && dataContextProhibitsMixedSecurityContexts(*document.frame()));
}

static void logConsoleWarning(const LocalFrame& frame, bool blocked, const URL& target, bool isUpgradingIPAddressAndLocalhostEnabled)
{
    auto isUpgradingLocalhostDisabled = !isUpgradingIPAddressAndLocalhostEnabled && shouldTreatAsPotentiallyTrustworthy(target);
    ASCIILiteral errorString = [&] {
    if (blocked)
        return "blocked and must"_s;
    if (isUpgradingLocalhostDisabled)
        return "not upgraded to HTTPS and must be served from the local host."_s;
    return "automatically upgraded and should"_s;
    }();

    auto message = makeString((!blocked ? ""_s : "[blocked] "_s), "The page at "_s, frame.document()->url().stringCenterEllipsizedToLength(), " requested insecure content from "_s, target.stringCenterEllipsizedToLength(), ". This content was "_s, errorString, !isUpgradingLocalhostDisabled ? " be served over HTTPS.\n"_s : "\n"_s);
    frame.protectedDocument()->addConsoleMessage(MessageSource::Security, MessageLevel::Warning, message);
}

static bool destinationIsImageAudioOrVideo(FetchOptions::Destination destination)
{
    return destination == FetchOptions::Destination::Audio || destination == FetchOptions::Destination::Image || destination == FetchOptions::Destination::Video;
}

static bool destinationIsImageAndInitiatorIsImageset(FetchOptions::Destination destination, Initiator initiator)
{
    return destination == FetchOptions::Destination::Image && initiator == Initiator::Imageset;
}

bool MixedContentChecker::shouldUpgradeInsecureContent(LocalFrame& frame, IsUpgradable isUpgradable, const URL& url, FetchOptions::Destination destination, Initiator initiator)
{
    RefPtr document = frame.document();
    if (!document || isUpgradable != IsUpgradable::Yes)
        return false;

    // https://www.w3.org/TR/mixed-content/#upgrade-algorithm
    // Editor’s Draft, 23 February 2023
    // 4.1. Upgrade request to an a priori authenticated URL as mixed content, if appropriate

    // 4.1.1.3 Does settings prohibit mixed security contexts? returns "Does Not Restrict Mixed Security Contents" when applied to request’s client.
    if (!prohibitsMixedSecurityContexts(*document))
        return false;

    // 4.1.1.1, 4.1.1.2, 4.1.1.4, 4.1.1.5
    if (!canModifyRequest(url, destination, initiator))
        return false;

    auto shouldUpgradeIPAddressAndLocalhostForTesting = document->settings().iPAddressAndLocalhostMixedContentUpgradeTestingEnabled();

    logConsoleWarning(frame, /* blocked */ false, url, shouldUpgradeIPAddressAndLocalhostForTesting);
    return true;
}

bool MixedContentChecker::canModifyRequest(const URL& url, FetchOptions::Destination destination, Initiator initiator)
{
    // 4.1.1.1 request’s URL is a potentially trustworthy URL.
    if (isNonLocalHostPotentiallyTrustworthyURL(url))
        return false;

    // 4.1.1.2 request’s URL’s host is an IP address.
    // We diverge from the spec when it comes to the loopback address, which consider as upgradable.
    if (URL::hostIsIPAddress(url.host()) && !SecurityOrigin::isLocalHostOrLoopbackIPAddress(url.host()))
        return false;

    // 4.1.1.4 request’s destination is not "image", "audio", or "video".
    if (!destinationIsImageAudioOrVideo(destination))
        return false;

    // 4.1.1.5 request’s destination is "image" and request’s initiator is "imageset".
    if (destinationIsImageAndInitiatorIsImageset(destination, initiator))
        return false;

    return true;
}

bool MixedContentChecker::shouldBlockRequest(LocalFrame& frame, const URL& url, IsUpgradable isUpgradable)
{
    if (isUpgradable == IsUpgradable::Yes)
        return false;

    // https://www.w3.org/TR/mixed-content/#upgrade-algorithm
    // Editor’s Draft, 23 February 2023
    // 4.4. Should fetching request be blocked as mixed content?

    RefPtr document = frame.document();
    if (!document)
        return false;

    // 4.4.1.1 Does settings prohibit mixed security contexts? returns "Does Not Restrict Mixed Security Contexts" when applied to request’s client.
    if (!prohibitsMixedSecurityContexts(*frame.document()))
        return false;

    // 4.4.1.2  request’s URL is a potentially trustworthy URL.
    if (isNonLocalHostPotentiallyTrustworthyURL(url))
        return false;

    // 4.4.1.3 The user agent has been instructed to allow mixed content, as described in § 7.2 User Controls).
    // 4.4.1.4 request’s destination is "document", and request’s target browsing context has no parent browsing context.

    logConsoleWarning(frame, /* blocked */ true, url, document->settings().iPAddressAndLocalhostMixedContentUpgradeTestingEnabled());
    return true;
}

void MixedContentChecker::checkFormForMixedContent(LocalFrame& frame, const URL& url)
{
    // Unconditionally allow javascript: URLs as form actions as some pages do this and it does not introduce
    // a mixed content issue.
    if (url.protocolIsJavaScript())
        return;

    if (!prohibitsMixedSecurityContexts(*frame.document()) || isNonLocalHostPotentiallyTrustworthyURL(url))
        return;

    auto message = makeString("The page at "_s, frame.document()->url().stringCenterEllipsizedToLength(), " contains a form which targets an insecure URL "_s, url.stringCenterEllipsizedToLength(), ".\n"_s);
    frame.protectedDocument()->addConsoleMessage(MessageSource::Security, MessageLevel::Warning, message);
}

} // namespace WebCore
