package org.catcert.gui;

import java.awt.Dimension;
import java.awt.Rectangle;

import javax.swing.JComboBox;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.plaf.basic.BasicComboPopup;
import javax.swing.plaf.basic.ComboPopup;
import javax.swing.plaf.metal.MetalComboBoxUI;

/**
 * 
 * @author oburgos
 *
 */
public class ComboBox extends JComboBox {

	private static final long serialVersionUID = 8501664702564433789L;

	protected int popupWidth;
	protected int popupHeight;

	public ComboBox(final Object[] items) {
		super(items);
		setMaximumRowCount(5);
		setUI(new ComboBoxUI());
		popupWidth = 0;
		popupHeight = 0;
	}

	public void setPopupWidth(int width, int height) {
		popupWidth = width;
		popupHeight = height;
	}

	public Dimension getPopupSize() {
		Dimension size = getSize();
		if (popupWidth < 1)
			popupWidth = size.width;
		if (popupHeight < 1)
			popupHeight = size.height;
		return new Dimension(popupWidth, popupHeight);
	}

	public class ComboBoxUI extends MetalComboBoxUI{
		protected ComboPopup createPopup(){			
			BasicComboPopup popup = new BasicComboPopup(comboBox){
				private static final long serialVersionUID = 6495335189854776644L;

				public void show() {
					Dimension popupSize = ((ComboBox)comboBox).getPopupSize();
					popupSize.setSize(popupSize.width, getPopupHeightForRowCount(comboBox.getMaximumRowCount())+18);
					
					Rectangle popupBounds = computePopupBounds(0, comboBox.getBounds().height, popupSize.width, popupSize.height);
					scroller.setMaximumSize(popupBounds.getSize());
					scroller.setPreferredSize(popupBounds.getSize());
					scroller.setMinimumSize(popupBounds.getSize());
					list.invalidate();
					int selectedIndex = comboBox.getSelectedIndex();
					if (selectedIndex == -1) {
						list.clearSelection();
					} else {
						list.setSelectedIndex(selectedIndex);
					}
					list.ensureIndexIsVisible(list.getSelectedIndex());
					setLightWeightPopupEnabled(comboBox.isLightWeightPopupEnabled());

					show(comboBox, popupBounds.x, popupBounds.y);
				}

				protected JScrollPane createScroller() {
					JScrollPane scroll = new JScrollPane(list, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
							ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
					scroll.setWheelScrollingEnabled(true);

					return scroll;
				}
			};

			popup.getAccessibleContext().setAccessibleParent(comboBox);
			return popup;
		}
	}
}
