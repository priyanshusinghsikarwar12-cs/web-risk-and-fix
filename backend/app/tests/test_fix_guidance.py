from app.services.fix_guidance import add_fix_guidance


CLOUDFLARE_TECHNOLOGY = {
    "checks": [
        {
            "name": "Traffic Protection Service",
            "value": "Cloudflare",
            "confidence": "High",
        }
    ]
}


def test_domain_renewal_gets_registrar_guidance_only():
    recommendations = add_fix_guidance(
        [
            {
                "title": "Renew your domain registration",
            }
        ],
        CLOUDFLARE_TECHNOLOGY,
    )

    guidance = recommendations[0]["guidance"]

    assert "how_to_fix" in guidance
    assert "platform_guidance" not in guidance


def test_dkim_gets_email_guidance_only():
    recommendations = add_fix_guidance(
        [
            {
                "title": "Fix your DKIM email signing",
            }
        ],
        CLOUDFLARE_TECHNOLOGY,
    )

    guidance = recommendations[0]["guidance"]

    assert "DKIM" in guidance["technical_name"]
    assert "platform_guidance" not in guidance


def test_header_can_receive_platform_guidance():
    recommendations = add_fix_guidance(
        [
            {
                "title": "Enable HTTPS Protection",
            }
        ],
        CLOUDFLARE_TECHNOLOGY,
    )

    guidance = recommendations[0]["guidance"]

    assert guidance["platform"] == "cloudflare"
    assert "platform_guidance" in guidance