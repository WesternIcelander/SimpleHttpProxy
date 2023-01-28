package io.siggi.simplehttpproxy.util;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class CaseInsensitiveHashMap<V> implements Map<String, V> {

    private final Map<String, V> map;
    private final Map<String, String> mappings;

    public CaseInsensitiveHashMap() {
        this.map = new HashMap<>();
        this.mappings = new HashMap<>();
    }

    private String getMapping(String str) {
        String lc = str.toLowerCase();
        String m = mappings.get(lc);
        if (m == null) {
            mappings.put(lc, m = str);
        }
        return m;
    }

    private void clearMapping(String str) {
        mappings.remove(str.toLowerCase());
    }

    @Override
    public int size() {
        return map.size();
    }

    @Override
    public boolean isEmpty() {
        return map.isEmpty();
    }

    @Override
    public boolean containsKey(Object k) {
        if (!(k instanceof String)) {
            return false;
        }
        String key = (String) k;
        if (!map.containsKey(getMapping(key))) {
            clearMapping(key);
            return false;
        }
        return true;
    }

    @Override
    public boolean containsValue(Object value) {
        return map.containsValue(value);
    }

    @Override
    public V get(Object k) {
        if (!(k instanceof String)) {
            return null;
        }
        String key = (String) k;
        return map.get(getMapping(key));
    }

    @Override
    public V put(String key, V value) {
        V old = map.remove(getMapping(key));
        clearMapping(key);
        map.put(getMapping(key), value);
        return old;
    }

    @Override
    public V remove(Object k) {
        if (!(k instanceof String)) {
            return null;
        }
        String key = (String) k;
        return map.remove(getMapping(key));
    }

    @Override
    public void putAll(Map<? extends String, ? extends V> m) {
        for (Map.Entry<? extends String, ? extends V> entry : m.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    @Override
    public void clear() {
        map.clear();
        mappings.clear();
    }

    @Override
    public Set<String> keySet() {
        return map.keySet();
    }

    @Override
    public Collection<V> values() {
        return map.values();
    }

    @Override
    public Set<Map.Entry<String, V>> entrySet() {
        return map.entrySet();
    }

}
