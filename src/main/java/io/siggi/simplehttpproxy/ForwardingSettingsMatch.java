package io.siggi.simplehttpproxy;

public final class ForwardingSettingsMatch {
    public final ForwardingSettings settings;
    public final int index;

    ForwardingSettingsMatch(ForwardingSettings settings, int index) {
        this.settings = settings;
        this.index = index;
    }
}
